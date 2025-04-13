const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);
const fs = require('fs').promises;
const path = require('path');
const axios = require('axios');
require('dotenv').config();

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

const asyncHandler = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(error => {
    if (!IS_PRODUCTION) console.error('Error:', error.message);
    res.status(500).json({ success: false, message: 'Server error occurred' });
  });

const validateEnv = () => {
  const required = ['AD_URL', 'AD_USERNAME', 'AD_PASSWORD', 'AD_SERVER', 'ADMIN_GROUP', 'TURNSTILE_SECRET_KEY'];
  const missing = required.filter(key => !process.env[key]);
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
    if (stderr && !stdout) {
      throw new Error('PowerShell execution failed');
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

app.post('/api/login', asyncHandler(async (req, res) => {
  const { username, password, turnstileToken } = req.body;
  if (!username || !password || !turnstileToken) {
    return res.status(400).json({ success: false, message: 'Username, password, and CAPTCHA token are required' });
  }

  const isValidCaptcha = await verifyTurnstileToken(turnstileToken);
  if (!isValidCaptcha) {
    return res.status(400).json({ success: false, message: 'Invalid CAPTCHA' });
  }

  const findUserCommand = `
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8;
    ${getCredString(adConfig.username, adConfig.password)}
    $user = Get-ADUser -Identity '${username}' -Server '${adConfig.server}' -Credential $cred -Properties UserPrincipalName,DisplayName,MemberOf -ErrorAction Stop;
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
      ${getCredString(fullUPN, password)}
      $user = Get-ADUser -Identity '${username}' -Server '${adConfig.server}' -Credential $cred -ErrorAction Stop;
      if ($user) {
        'Authentication successful'
      } else {
        Write-Error 'Authentication failed'
        exit 1
      }
    `;
    await execPS(authCommand);

    res.json({
      success: true,
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

app.post('/api/change-ad-password', asyncHandler(async (req, res) => {
  const { username, newPassword } = req.body;
  if (!username || !newPassword) {
    return res.status(400).json({ success: false, message: 'Username and new password are required' });
  }

  const command = `
    ${getCredString(adConfig.username, adConfig.password)}
    Set-ADAccountPassword -Identity '${username}' -NewPassword (ConvertTo-SecureString '${newPassword}' -AsPlainText -Force) -Server '${adConfig.server}' -Credential $cred -ErrorAction Stop;
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

app.post('/api/change-azure-password', asyncHandler(async (req, res) => {
  const { username, newPassword } = req.body;
  if (!username || !newPassword) {
    return res.status(400).json({ success: false, message: 'Username and new password are required' });
  }

  const findUserCommand = `
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8;
    ${getCredString(adConfig.username, adConfig.password)}
    $user = Get-ADUser -Identity '${username}' -Server '${adConfig.server}' -Credential $cred -Properties UserPrincipalName -ErrorAction Stop;
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
    Set-MsolUserPassword -UserPrincipalName '${azureUsername}' -NewPassword '${newPassword}' -ForceChangePassword $false -ErrorAction Stop | Out-Null;
    'Azure password changed successfully'
  `;
  try {
    await execPS(command);
    res.json({ success: true, message: 'Azure AD password changed successfully' });
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Azure Password Change Error:', error.message);
    await storePendingChange(username, newPassword);
    res.status(500).json({
      success: false,
      message: 'Azure AD password change failed. Will retry later.',
    });
  }
}));

app.post('/api/generate-code', asyncHandler(async (req, res) => {
  const { secretCode, username } = req.body;
  if (!secretCode || !username) {
    return res.status(400).json({ success: false, message: 'Secret code and username are required' });
  }

  try {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const formattedDate = `${year}-${month}-${day} ${hours}:${minutes}`;

    console.log(`Generating secret code: ${secretCode} || ${username} || ${formattedDate}`);

    const newLine = `${secretCode} || ${username} || ${formattedDate}\n`;

    let fileContent = '';
    try {
      fileContent = await fs.readFile(SECRET_CODE_FILE, 'utf8');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }

    if (fileContent && !fileContent.endsWith('\n')) {
      await fs.appendFile(SECRET_CODE_FILE, '\n');
    }

    await fs.appendFile(SECRET_CODE_FILE, newLine);
    res.json({ success: true, message: 'Secret code generated successfully' });
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Generate Code Error:', error.message);
    res.status(500).json({ success: false, message: 'Failed to generate secret code' });
  }
}));

app.post('/api/reset-password', asyncHandler(async (req, res) => {
  const { username, secretCode } = req.body;

  if (!username || !secretCode) {
    return res.status(400).json({ success: false, message: 'Username and secret code are required' });
  }

  try {
    const fileContent = await fs.readFile(SECRET_CODE_FILE, 'utf8');
    const lines = fileContent.trim().split('\n');
    let updatedLines = [...lines];
    const now = new Date();
    const TWENTY_MINUTES_MS = 20 * 60 * 1000;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.startsWith('#EXPIRED#') || line.startsWith('#VALIDATED#')) continue;

      const [storedCode, storedUsername, timeStr] = line.split(' || ').map(part => part.trim());
      if (!storedCode || !storedUsername || !timeStr) continue;

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

      const [storedCode, storedUsername, timeStr] = line.split(' || ').map(part => part.trim());
      if (!storedCode || !storedUsername || !timeStr) continue;

      if (storedUsername === username && storedCode === secretCode) {
        foundMatch = true;
        matchIndex = i;
        break;
      }
    }

    if (!foundMatch) {
      return res.status(401).json({ success: false, message: 'Invalid secret code' });
    }

    updatedLines[matchIndex] = `#VALIDATED# ${lines[matchIndex]}`;
    await fs.writeFile(SECRET_CODE_FILE, updatedLines.join('\n'), 'utf8');
    if (!IS_PRODUCTION) console.log('Validated secret code');

    res.json({
      success: true,
      username,
      displayName: username,
      isAdmin: false, // Explicitly indicate non-admin status
    });
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Reset Password Error:', error.message);
    res.status(500).json({ success: false, message: 'Server error occurred' });
  }
}));

const storePendingChange = async (username, newPassword) => {
  try {
    const pending = await getPendingChanges();
    pending.push({ username, newPassword, timestamp: Date.now() });
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

    for (const { username, newPassword } of pending) {
      const findUserCommand = `
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8;
        ${getCredString(adConfig.username, adConfig.password)}
        $user = Get-ADUser -Identity '${username}' -Server '${adConfig.server}' -Credential $cred -Properties UserPrincipalName -ErrorAction Stop;
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
          Set-MsolUserPassword -UserPrincipalName '${azureUsername}' -NewPassword '${newPassword}' -ForceChangePassword $false -ErrorAction Stop | Out-Null;
          'Azure password changed successfully'
        `;
        await execPS(command);
        if (!IS_PRODUCTION) console.log(`Retry succeeded for ${username}`);
      } catch (error) {
        if (!IS_PRODUCTION) console.error(`Retry failed for ${username}:`, error.message);
        updatedPending.push({ username, newPassword, timestamp: Date.now() });
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