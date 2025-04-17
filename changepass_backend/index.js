const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);
const fs = require('fs').promises;
const path = require('path');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const sanitizeInput = (input) => {
  return input.replace(/['";`]/g, '').replace(/\s+/g, ' ').trim();
};

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use((req, res, next) => {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  next();
});

const adConfig = {
  url: process.env.AD_URL,
  username: process.env.AD_USERNAME,
  password: process.env.AD_PASSWORD,
  server: process.env.AD_SERVER,
  adminGroup: process.env.ADMIN_GROUP,
};

const PENDING_FILE = path.join(__dirname, 'pending-azure-changes.json');
const SECRET_CODE_FILE = path.join(__dirname, 'secrets/reset_password.code');
const PORT = process.env.PORT || 3001;
const RETRY_INTERVAL = 300000; // 5 minutes
const TWENTY_MINUTES = 20 * 60 * 1000; // 20 minutes in milliseconds
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY;
const MAX_RETRIES = 5;
const EXPIRY_HOURS = 24;

const asyncHandler = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(error => {
    if (!IS_PRODUCTION) console.error('Error:', error.message);
    res.status(500).json({ success: false, message: 'Server error occurred' });
  });

const validateEnv = () => {
  const required = ['AD_URL', 'AD_USERNAME', 'AD_PASSWORD', 'AD_SERVER', 'ADMIN_GROUP', 'TURNSTILE_SECRET_KEY', 'JWT_SECRET'];
  const missing = required.filter(key => !process.env[key] || process.env[key].trim() === '');
  if (missing.length) throw new Error(`Missing environment variables: ${missing.join(', ')}`);
};

const verifyTurnstileToken = async (token) => {
  try {
    const response = await axios.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      secret: TURNSTILE_SECRET_KEY,
      response: token,
    });
    return response.data.success;
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Turnstile Verification Error:', error.message);
    return false;
  }
};

const initializePendingFile = async () => {
  try {
    await fs.access(PENDING_FILE);
  } catch {
    await fs.writeFile(PENDING_FILE, '[]');
  }
};

const initializeSecretCodeFile = async () => {
  try {
    await fs.access(SECRET_CODE_FILE);
  } catch {
    await fs.mkdir(path.dirname(SECRET_CODE_FILE), { recursive: true });
    await fs.writeFile(SECRET_CODE_FILE, ''); // Initialize as empty text file
  }
};

const execPS = async (command) => {
  try {
    const encodedCommand = Buffer.from(`
      $ProgressPreference = 'SilentlyContinue';
      If (-Not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error 'ActiveDirectory module is not installed'
        Exit 1
      }
      If (-Not (Get-Module -ListAvailable -Name MSOnline)) {
        Write-Error 'MSOnline module is not installed'
        Exit 1
      }
      Import-Module ActiveDirectory
      Import-Module MSOnline
      ${command}
    `, 'utf16le').toString('base64');

    const { stdout, stderr } = await exec(`powershell -EncodedCommand "${encodedCommand}"`, {
      encoding: 'utf8',
      timeout: 30000,
      maxBuffer: 1024 * 1024
    });
    /*if (stderr && !stdout) {
      throw new Error('PowerShell execution failed');
    }*/
    if (stderr && stderr.includes('Error')) {
      throw new Error(`PowerShell error: ${stderr}`);
    }
    if (!stdout.trim()) {
      throw new Error('No output from PowerShell');
    }
    return stdout.trim();
  } catch (error) {
    if (!IS_PRODUCTION) console.error('ExecPS Error:', error.message);
    throw error;
  }
};

const getCredString = (username, password) => {
  const escapedPassword = password.replace(/'/g, "''").replace(/"/g, '""');
  return `$cred = New-Object System.Management.Automation.PSCredential('${username}', (ConvertTo-SecureString '${escapedPassword}' -AsPlainText -Force));`;
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Expecting "Bearer <token>"
  if (!token) {
    return res.status(401).json({ success: false, message: 'Authentication token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    }
    req.user = user; // Save user info for the endpoint
    next(); // Let the request continue
  });
};

// Rate limiter for /api/login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per IP
  message: { success: false, message: 'Too many login attempts. Please try again later.' },
});

// Rate limiter for /api/reset-password
const resetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 requests per IP
  message: { success: false, message: 'Too many reset attempts. Please try again later.' },
});

app.post('/api/login', loginLimiter, asyncHandler(async (req, res) => {
  const { username, password, turnstileToken } = req.body;
  if (!username || !password || !turnstileToken) {
    return res.status(400).json({ success: false, message: 'Username, password, and CAPTCHA token are required' });
  }

  const isValidCaptcha = await verifyTurnstileToken(turnstileToken);
  if (!isValidCaptcha) {
    return res.status(400).json({ success: false, message: 'Invalid CAPTCHA' });
  }

  const sanitizedUsername = sanitizeInput(username);
  const sanitizedPassword = sanitizeInput(password);

  const findUserCommand = `
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8;
    ${getCredString(adConfig.username, adConfig.password)}
    $user = Get-ADUser -Identity '${sanitizedUsername}' -Server '${adConfig.server}' -Credential $cred -Properties UserPrincipalName,DisplayName,MemberOf -ErrorAction Stop;
    $adminGroup = Get-ADGroup -Identity '${adConfig.adminGroup}' -Server '${adConfig.server}' -Credential $cred -ErrorAction Stop;
    $isAdmin = $user.MemberOf -contains $adminGroup.DistinguishedName;
    if ($user) {
      $user | Select-Object -Property SamAccountName,UserPrincipalName,DisplayName,@{Name='IsAdmin';Expression={$isAdmin}} | ConvertTo-Json -Compress
    } else {
      Write-Error 'User not found'
      exit 1
    }
  `;
  try {
    const findStdout = await execPS(findUserCommand);
    let userData;
    try {
      userData = JSON.parse(findStdout);
    } catch (parseError) {
      if (!IS_PRODUCTION) console.error('JSON Parse Error:', parseError.message);
      throw new Error('Invalid user data');
    }
    if (!userData.UserPrincipalName) {
      throw new Error('UserPrincipalName missing');
    }
    const fullUPN = userData.UserPrincipalName;

    const authCommand = `
      [Console]::OutputEncoding = [System.Text.Encoding]::UTF8;
      ${getCredString(fullUPN, sanitizedPassword)}
      $user = Get-ADUser -Identity '${sanitizedUsername}' -Server '${adConfig.server}' -Credential $cred -ErrorAction Stop;
      if ($user) {
        'Authentication successful'
      } else {
        Write-Error 'Authentication failed'
        exit 1
      }
    `;
    await execPS(authCommand);

    // Generate JWT
    const token = jwt.sign(
      { username: userData.SamAccountName, isAdmin: userData.IsAdmin },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      success: true,
      token, // Send the JWT to the frontend
      username: userData.SamAccountName || username,
      displayName: userData.DisplayName || username,
      isAdmin: userData.IsAdmin || false,
    });
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Login Error:', error.message);
    res.status(401).json({ success: false, message: 'Invalid username or password' });
  }
}));

app.post('/api/logout', (req, res) => {
  res.json({ success: true, message: 'Logged out successfully' });
});

app.post('/api/change-ad-password', authenticateToken, asyncHandler(async (req, res) => {
  const { username, newPassword } = req.body;
  if (!username || !newPassword) {
    return res.status(400).json({ success: false, message: 'Username and new password are required' });
  }
  if (username !== req.user.username) {
    return res.status(403).json({ success: false, message: 'Unauthorized: You can only change your own password' });
  }

  const sanitizedUsername = sanitizeInput(username);
  const sanitizedPassword = sanitizeInput(newPassword);

  const command = `
    ${getCredString(adConfig.username, adConfig.password)}
    Set-ADAccountPassword -Identity '${sanitizedUsername}' -NewPassword (ConvertTo-SecureString '${sanitizedPassword}' -AsPlainText -Force) -Server '${adConfig.server}' -Credential $cred -ErrorAction Stop;
    'Password changed successfully'
  `;
  try {
    await execPS(command);
    res.json({ success: true, message: 'AD password changed successfully' });
  } catch (error) {
    if (!IS_PRODUCTION) console.error('AD Password Change Error:', error.message);
    res.status(500).json({ success: false, message: 'Failed to change AD password' });
  }
}));

app.post('/api/change-azure-password', authenticateToken, asyncHandler(async (req, res) => {
  const { username, newPassword } = req.body;
  if (!username || !newPassword) {
    return res.status(400).json({ success: false, message: 'Username and new password are required' });
  }
  if (username !== req.user.username) {
    return res.status(403).json({ success: false, message: 'Unauthorized: You can only change your own password' });
  }

  const sanitizedUsername = sanitizeInput(username);
  const sanitizedPassword = sanitizeInput(newPassword);

  const findUserCommand = `
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8;
    ${getCredString(adConfig.username, adConfig.password)}
    $user = Get-ADUser -Identity '${sanitizedUsername}' -Server '${adConfig.server}' -Credential $cred -Properties UserPrincipalName -ErrorAction Stop;
    if ($user) {
      $user | Select-Object -Property UserPrincipalName | ConvertTo-Json -Compress
    } else {
      Write-Error 'User not found'
      exit 1
    }
  `;
  let userData;
  try {
    const findStdout = await execPS(findUserCommand);
    try {
      userData = JSON.parse(findStdout);
    } catch (parseError) {
      if (!IS_PRODUCTION) console.error('JSON Parse Error:', parseError.message);
      throw new Error('Invalid user data');
    }
    if (!userData.UserPrincipalName) {
      throw new Error('UserPrincipalName missing');
    }
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Find User Error:', error.message);
    throw error;
  }

  const azureUsername = userData.UserPrincipalName;
  const command = `
    ${getCredString(adConfig.username, adConfig.password)}
    Connect-MsolService -Credential $cred -ErrorAction Stop;
    Set-MsolUserPassword -UserPrincipalName '${azureUsername}' -NewPassword '${sanitizedPassword}' -ForceChangePassword $false -ErrorAction Stop | Out-Null;
    'Azure password changed successfully'
  `;
  try {
    await execPS(command);
    res.json({ success: true, message: 'Azure AD password changed successfully' });
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Azure Password Change Error:', error.message);
    await storePendingChange(sanitizedUsername, sanitizedPassword);
    res.status(500).json({
      success: false,
      message: 'Azure AD password change failed. Will retry later.',
    });
  }
}));

const manageSecretCodeFile = async () => {
  try {
    const VALIDATED_LOG_FILE = path.join(__dirname, 'secrets/validated_codes.log');
    const fileContent = await fs.readFile(SECRET_CODE_FILE, 'utf8');
    const lines = fileContent.trim().split('\n').filter(line => line);
    const now = new Date();
    const validatedLines = [];
    const activeLines = [];

    // Process each line
    for (const line of lines) {
      if (line.startsWith('#EXPIRED#')) {
        continue; // Skip expired lines
      } else if (line.startsWith('#VALIDATED#')) {
        validatedLines.push(line.replace('#VALIDATED# ', '')); // Store validated without prefix
      } else {
        activeLines.push(line); // Keep active codes
      }
    }

    // Write back only active lines to reset_password.code
    await fs.writeFile(SECRET_CODE_FILE, activeLines.join('\n') + (activeLines.length ? '\n' : ''));

    // Append validated lines to validated_codes.log
    if (validatedLines.length) {
      await fs.mkdir(path.dirname(VALIDATED_LOG_FILE), { recursive: true });
      // const logEntry = validatedLines.map(line => `${new Date().toISOString()} || ${line}`).join('\n') + '\n';
      const logEntry = validatedLines.map(line => `${line}`).join('\n') + '\n';
      await fs.appendFile(VALIDATED_LOG_FILE, logEntry);
    }

    return true;
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Manage Secret Code File Error:', error.message);
    throw new Error('Failed to manage secret code file');
  }
};

app.post('/api/generate-code', authenticateToken, asyncHandler(async (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ success: false, message: 'Admin access required' });
  }
  const { secretCode, username } = req.body;
  if (!secretCode || !username) {
    return res.status(400).json({ success: false, message: 'Secret code and username are required' });
  }

  // Validate secret code
  if (secretCode.length < 8 || /\s/.test(secretCode)) {
    return res.status(400).json({ success: false, message: 'Secret code must be at least 8 characters long and contain no spaces' });
  }

  const sanitizedUsername = sanitizeInput(username);
  const sanitizedSecretCode = sanitizeInput(secretCode);

  try {
    await manageSecretCodeFile();

    // Hash the secret code
    const hashedCode = await bcrypt.hash(sanitizedSecretCode, 10); // 10 is the salt rounds

    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const formattedDate = `${year}-${month}-${day} ${hours}:${minutes}`;

    if (!IS_PRODUCTION) console.log(`Generating secret code for ${sanitizedUsername} || ${formattedDate}`);

    const newLine = `${hashedCode} || ${sanitizedUsername} || ${formattedDate}\n`;

    await fs.appendFile(SECRET_CODE_FILE, newLine);

    res.json({ success: true, message: 'Secret code generated successfully' });
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Generate Code Error:', error.message);
    res.status(500).json({ success: false, message: 'Failed to generate secret code' });
  }
}));

app.post('/api/reset-password', resetLimiter, asyncHandler(async (req, res) => {
  const { username, secretCode } = req.body;
  if (!username || !secretCode) {
    return res.status(400).json({ success: false, message: 'Username and secret code are required' });
  }

  const sanitizedUsername = sanitizeInput(username);
  const sanitizedSecretCode = sanitizeInput(secretCode);

  try {
    const fileContent = await fs.readFile(SECRET_CODE_FILE, 'utf8');
    const lines = fileContent.trim().split('\n');
    let updatedLines = [...lines];
    const now = new Date();
    const TWENTY_MINUTES_MS = 20 * 60 * 1000;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.startsWith('#EXPIRED#') || line.startsWith('#VALIDATED#')) continue;

      const [storedHash, storedUsername, timeStr] = line.split(' || ').map(part => part.trim());
      if (!storedHash || !storedUsername || !timeStr) continue;

      const storedDate = new Date(timeStr);
      if (isNaN(storedDate.getTime())) {
        if (!IS_PRODUCTION) console.warn('Invalid date-time format in line:', line);
        continue;
      }

      const timeDiffMs = now - storedDate;
      if (timeDiffMs > TWENTY_MINUTES_MS || timeDiffMs < 0) {
        updatedLines[i] = `#EXPIRED# ${line}`;
        if (!IS_PRODUCTION) console.log('Marked as expired:', line);
      }
    }

    await fs.writeFile(SECRET_CODE_FILE, updatedLines.join('\n'), 'utf8');
    if (!IS_PRODUCTION) console.log('Updated reset_password.code with expired entries');

    let foundMatch = false;
    let matchIndex = -1;

    for (let i = 0; i < updatedLines.length; i++) {
      const line = updatedLines[i];
      if (line.startsWith('#EXPIRED#') || line.startsWith('#VALIDATED#')) continue;

      const [storedHash, storedUsername, timeStr] = line.split(' || ').map(part => part.trim());
      if (!storedHash || !storedUsername || !timeStr) continue;

      if (storedUsername === sanitizedUsername) {
        // Compare the entered code with the stored hash
        const isMatch = await bcrypt.compare(sanitizedSecretCode, storedHash);
        if (isMatch) {
          foundMatch = true;
          matchIndex = i;
          break;
        }
      }
    }

    if (!foundMatch) {
      return res.status(401).json({ success: false, message: 'Invalid secret code' });
    }

    updatedLines[matchIndex] = `#VALIDATED# ${lines[matchIndex]}`;
    await fs.writeFile(SECRET_CODE_FILE, updatedLines.join('\n'), 'utf8');
    if (!IS_PRODUCTION) console.log('Validated secret code');

    const tempToken = jwt.sign(
      { username: sanitizedUsername, isAdmin: false },
      process.env.JWT_SECRET,
      { expiresIn: '10m' }
    );

    res.json({
      success: true,
      token: tempToken,
      username: sanitizedUsername,
      displayName: sanitizedUsername,
    });
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Reset Password Error:', error.message);
    res.status(500).json({ success: false, message: 'Server error occurred' });
  }
}));

const storePendingChange = async (username, newPassword) => {
  try {
    const sanitizedUsername = sanitizeInput(username);
    const sanitizedPassword = sanitizeInput(newPassword);
    const pending = await getPendingChanges();
    pending.push({ username: sanitizedUsername, newPassword: sanitizedPassword, timestamp: Date.now(), retries: 0 });
    await fs.writeFile(PENDING_FILE, JSON.stringify(pending, null, 2));
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Store Pending Change Error:', error.message);
  }
};

const getPendingChanges = async () => {
  try {
    const data = await fs.readFile(PENDING_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Get Pending Changes Error:', error.message);
    return [];
  }
};

const retryPendingChanges = async () => {
  try {
    const pending = await getPendingChanges();
    if (!pending.length) return;
    const updatedPending = [];
    const MAX_RETRIES = 5;
    const EXPIRY_HOURS = 24;
    const now = Date.now();

    for (const { username, newPassword, timestamp, retries = 0 } of pending) {
      if (retries >= MAX_RETRIES || now - timestamp > EXPIRY_HOURS * 60 * 60 * 1000) {
        if (!IS_PRODUCTION) console.log(`Expiring change for ${username}: ${retries >= MAX_RETRIES ? 'Max retries reached' : 'Expired'}`);
        continue;
      }

      const sanitizedUsername = sanitizeInput(username);
      const sanitizedPassword = sanitizeInput(newPassword);

      const findUserCommand = `
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8;
        ${getCredString(adConfig.username, adConfig.password)}
        $user = Get-ADUser -Identity '${sanitizedUsername}' -Server '${adConfig.server}' -Credential $cred -Properties UserPrincipalName -ErrorAction Stop;
        if ($user) {
          $user | Select-Object -Property UserPrincipalName | ConvertTo-Json -Compress
        } else {
          Write-Error 'User not found'
          exit 1
        }
      `;
      try {
        const findStdout = await execPS(findUserCommand);
        let userData;
        try {
          userData = JSON.parse(findStdout);
        } catch (parseError) {
          if (!IS_PRODUCTION) console.error('JSON Parse Error:', parseError.message);
          throw new Error('Invalid user data');
        }
        const azureUsername = userData.UserPrincipalName;
        if (!azureUsername) {
          throw new Error('UserPrincipalName missing');
        }

        const command = `
          ${getCredString(adConfig.username, adConfig.password)}
          Connect-MsolService -Credential $cred -ErrorAction Stop;
          Set-MsolUserPassword -UserPrincipalName '${azureUsername}' -NewPassword '${sanitizedPassword}' -ForceChangePassword $false -ErrorAction Stop | Out-Null;
          'Azure password changed successfully'
        `;
        await execPS(command);
        if (!IS_PRODUCTION) console.log(`Retry succeeded for ${sanitizedUsername}`);
      } catch (error) {
        if (!IS_PRODUCTION) console.error(`Retry failed for ${sanitizedUsername}:`, error.message);
        updatedPending.push({ username: sanitizedUsername, newPassword: sanitizedPassword, timestamp, retries: retries + 1 });
      }
    }
    await fs.writeFile(PENDING_FILE, JSON.stringify(updatedPending, null, 2));
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Retry Pending Changes Error:', error.message);
  }
};

const startServer = async () => {
  try {
    validateEnv();
    await initializePendingFile();
    await initializeSecretCodeFile();
    setInterval(retryPendingChanges, RETRY_INTERVAL);
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT} in ${IS_PRODUCTION ? 'production' : 'development'} mode`);
    });
  } catch (error) {
    console.error('Startup failed:', error.message);
    process.exit(1);
  }
};

startServer();