const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);
const fs = require('fs').promises;
const path = require('path');
const axios = require('axios');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const winston = require('winston');
require('dotenv').config();

const app = express();

const logger = winston.createLogger({
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

const sanitizeInput = (input) => {
  if (typeof input !== 'string') {
    logger.warn('Non-string input detected');
    return '';
  }
  const maxLength = 256;
  const sanitized = input
    .replace(/['";`]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength);
  if (sanitized !== input) {
    logger.info(`Input sanitized: original="${input}", sanitized="${sanitized}"`);
  }
  return sanitized;
};

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

const graphConfig = {
  clientId: process.env.GRAPH_CLIENT_ID,
  tenantId: process.env.GRAPH_TENANT_ID,
  clientSecret: process.env.GRAPH_CLIENT_SECRET,
};

const PENDING_FILE = path.join(__dirname, 'pending-azure-changes.json');
const SECRET_CODE_FILE = path.join(__dirname, 'secrets/reset_password_code.json');
const VALIDATED_LOG_FILE = path.join(__dirname, 'secrets/validated_codes.log');
const BRUTAL_ATTEMPT_FILE = path.join(__dirname, 'block_brutal_attempt.json');
const BRUTAL_ATTEMPT_LOG = path.join(__dirname, 'block_brutal_attempt.log');
const PORT = process.env.PORT || 3001;
const RETRY_INTERVAL = 300000;
const TWENTY_MINUTES = 20 * 60 * 1000;
const RATE_LIMIT_WINDOW = 10 * 60 * 1000; // 10 minutes
const RATE_LIMIT_MAX = 5;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY;
const BCRYPT_COST = 12;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-jwt-secret';
const JWT_EXPIRES_IN = '1h';
const MAX_RETRIES = 5;
const EXPIRY_HOURS = 24;

const asyncHandler = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(error => {
    if (!IS_PRODUCTION) console.error('Error:', error.message);
    logger.error(`Error: ${error.message}`);
    res.status(500).json({ success: false, message: 'Server error occurred' });
  });

const validateEnv = () => {
  const required = ['AD_URL', 'AD_USERNAME', 'AD_PASSWORD', 'AD_SERVER', 'ADMIN_GROUP', 'TURNSTILE_SECRET_KEY', 'JWT_SECRET'];
  const missing = required.filter(key => !process.env[key] || process.env[key].trim() === '');
  if (missing.length) throw new Error(`Missing environment variables: ${missing.join(', ')}`);
};

// Validate Graph-specific environment variables separately
const validateGraphEnv = () => {
  const required = ['GRAPH_CLIENT_ID', 'GRAPH_TENANT_ID', 'GRAPH_CLIENT_SECRET'];
  const missing = required.filter(key => !process.env[key] || process.env[key].trim() === '');
  if (missing.length) throw new Error(`Missing Graph environment variables: ${missing.join(', ')}`);
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
    logger.error(`Turnstile Verification Error: ${error.message}`);
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
    await fs.writeFile(SECRET_CODE_FILE, '[]');
  }
};

const initializeBrutalAttemptFile = async () => {
  try {
    await fs.access(BRUTAL_ATTEMPT_FILE);
  } catch {
    await fs.mkdir(path.dirname(BRUTAL_ATTEMPT_FILE), { recursive: true });
    await fs.writeFile(BRUTAL_ATTEMPT_FILE, '[]');
  }
};

const checkRateLimit = async (username, endpoint, ip, isFailure) => {
  try {
    await initializeBrutalAttemptFile();
    const data = await fs.readFile(BRUTAL_ATTEMPT_FILE, 'utf8');
    let entries = JSON.parse(data || '[]');
    const now = Date.now();
    const nonActiveEntries = [];

    entries = entries.filter(entry => {
      if (entry.status !== 'active') {
        nonActiveEntries.push({
          ...entry,
          movedAt: new Date().toISOString()
        });
        return false;
      }
      return true;
    });

    if (nonActiveEntries.length) {
      const logEntries = nonActiveEntries.map(entry =>
        `${entry.movedAt} || ${entry.username} || ${entry.endpoint} || ${entry.attempts} || ${entry.timestamp} || ${entry.ip}`
      ).join('\n') + '\n';
      await fs.appendFile(BRUTAL_ATTEMPT_LOG, logEntries);
      logger.info(`Moved ${nonActiveEntries.length} non-active rate limit entries to block_brutal_attempt.log`);
    }

    let entry = entries.find(e => e.username === username && e.endpoint === endpoint && e.status === 'active');
    if (entry) {
      const entryDate = new Date(entry.timestamp);
      if (isNaN(entryDate.getTime())) {
        logger.warn(`Invalid timestamp in rate limit entry: ${JSON.stringify(entry)}`);
        entry.status = 'expired';
      } else if (now - entryDate.getTime() > RATE_LIMIT_WINDOW) {
        entry.status = 'expired';
      } else if (entry.attempts >= RATE_LIMIT_MAX) {
        const timeLeft = Math.ceil((RATE_LIMIT_WINDOW - (now - entryDate.getTime())) / 1000 / 60);
        logger.warn(`Rate limit exceeded for username ${username} on ${endpoint} from IP ${ip}`);
        return {
          allowed: false,
          message: `Too many ${endpoint} attempts for this username, please try again after ${timeLeft} minutes`
        };
      }
    }

    if (isFailure) {
      if (entry) {
        entry.attempts += 1;
        entry.ip = ip;
      } else {
        const now = new Date();
        const formattedDate = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')} ${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
        entries.push({
          username,
          endpoint,
          attempts: 1,
          timestamp: formattedDate,
          status: 'active',
          ip
        });
      }
    } else if (entry) {
      entry.status = 'validated';
      entry.ip = ip;
    }

    await fs.writeFile(BRUTAL_ATTEMPT_FILE, JSON.stringify(entries, null, 2));
    return { allowed: true };
  } catch (error) {
    logger.error(`Rate limit check error: ${error.message}`);
    return { allowed: true };
  }
};

// For AD-related commands (login, change-ad-password)
const execPS = async (command) => {
  try {
    const encodedCommand = Buffer.from(`
      $ProgressPreference = 'SilentlyContinue';
      If (-Not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error 'ActiveDirectory module is not installed'
        Exit 1
      }
      Import-Module ActiveDirectory
      ${command}
    `, 'utf16le').toString('base64');

    const { stdout, stderr } = await exec(`powershell -EncodedCommand "${encodedCommand}"`, {
      encoding: 'utf8',
      timeout: 30000,
      maxBuffer: 1024 * 1024
    });
    if (stderr && stderr.includes('Error')) {
      throw new Error(`PowerShell error: ${stderr}`);
    }
    if (!stdout.trim()) {
      throw new Error('No output from PowerShell');
    }
    return stdout.trim();
  } catch (error) {
    if (!IS_PRODUCTION) console.error('ExecPS Error:', error.message);
    logger.error(`ExecPS Error: ${error.message}`);
    throw error;
  }
};

// For Graph-related commands (change-azure-password)
const execPSGraph = async (command) => {
  try {
    const encodedCommand = Buffer.from(`
      $ProgressPreference = 'SilentlyContinue';
      If (-Not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error 'ActiveDirectory module is not installed'
        Exit 1
      }
      If (-Not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Write-Error 'Microsoft.Graph module is not installed'
        Exit 1
      }
      Import-Module ActiveDirectory
      Import-Module Microsoft.Graph
      ${command}
    `, 'utf16le').toString('base64');

    const { stdout, stderr } = await exec(`powershell -EncodedCommand "${encodedCommand}"`, {
      encoding: 'utf8',
      timeout: 30000,
      maxBuffer: 1024 * 1024
    });
    if (stderr && stderr.includes('Error')) {
      throw new Error(`PowerShell error: ${stderr}`);
    }
    if (!stdout.trim()) {
      throw new Error('No output from PowerShell');
    }
    return stdout.trim();
  } catch (error) {
    if (!IS_PRODUCTION) console.error('ExecPSGraph Error:', error.message);
    logger.error(`ExecPSGraph Error: ${error.message}`);
    throw error;
  }
};

const getCredString = (username, password) => {
  const escapedPassword = password.replace(/'/g, "''").replace(/"/g, '""');
  return `$cred = New-Object System.Management.Automation.PSCredential('${username}', (ConvertTo-SecureString '${escapedPassword}' -AsPlainText -Force));`;
};

const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    logger.warn('Missing or invalid Authorization header');
    return res.status(401).json({ success: false, message: 'Unauthorized: No token provided' });
  }

  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      logger.warn(`JWT verification failed: ${err.message}`);
      return res.status(401).json({ success: false, message: 'Unauthorized: Invalid or expired token' });
    }
    req.user = decoded;
    next();
  });
};

const verifyAdmin = (req, res, next) => {
  if (!req.user.isAdmin) {
    logger.warn(`Non-admin user attempted admin action: ${req.user.username}`);
    return res.status(403).json({ success: false, message: 'Forbidden: Admin access required' });
  }
  next();
};

app.post('/api/login', asyncHandler(async (req, res) => {
  let { username, password, turnstileToken } = req.body;
  username = sanitizeInput(username);
  password = sanitizeInput(password);
  if (!username || !password || !turnstileToken) {
    return res.status(400).json({ success: false, message: 'Username, password, and CAPTCHA token are required' });
    required', refreshCaptcha: true });
  }

  const isValidCaptcha = await verifyTurnstileToken(turnstileToken);
  if (!isValidCaptcha) {
    const rateLimitCheck = await checkRateLimit(username, 'login', req.ip, true);
    if (!rateLimitCheck.allowed) {
      return res.status(429).json({ success: false, message: rateLimitCheck.message, refreshCaptcha: true });
    }
    return res.status(400).json({ success: false, message: 'Invalid CAPTCHA', refreshCaptcha: true });
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
      logger.error(`JSON Parse Error: ${parseError.message}`);
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

    const rateLimitCheck = await checkRateLimit(username, 'login', req.ip, false);
    if (!rateLimitCheck.allowed) {
      return res.status(429).json({ success: false, message: rateLimitCheck.message, refreshCaptcha: true });
    }

    const token = jwt.sign(
      {
        username: userData.SamAccountName || username,
        displayName: userData.DisplayName || username,
        isAdmin: userData.IsAdmin || false,
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.json({
      success: true,
      token,
      username: userData.SamAccountName || username,
      displayName: userData.DisplayName || username,
      isAdmin: userData.IsAdmin || false,
    });
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Login Error:', error.message);
    logger.error(`Login Error: ${error.message}`);
    const rateLimitCheck = await checkRateLimit(username, 'login', req.ip, true);
    if (!rateLimitCheck.allowed) {
      return res.status(429).json({ success: false, message: rateLimitCheck.message, refreshCaptcha: true });
    }
    return res.status(401).json({ success: false, message: 'Invalid username or password', errorDetails: error.message, refreshCaptcha: true });
  }
}));

app.post('/api/logout', verifyJWT, asyncHandler(async (req, res) => {
  res.json({ success: true, message: 'Logged out successfully' });
}));

app.post('/api/change-ad-password', verifyJWT, asyncHandler(async (req, res) => {
  let { newPassword } = req.body;
  const username = req.user.username;
  newPassword = sanitizeInput(newPassword);
  if (!newPassword) {
    return res.status(400).json({ success: false, message: 'New password is required' });
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
    logger.error(`AD Password Change Error: ${error.message}`);
    res.status(500).json({ success: false, message: 'Failed to change AD password' });
  }
}));

app.post('/api/change-azure-password', verifyJWT, asyncHandler(async (req, res) => {
  let { newPassword } = req.body;
  const username = req.user.username;
  newPassword = sanitizeInput(newPassword);
  if (!newPassword) {
    return res.status(400).json({ success: false, message: 'New password is required' });
  }

  // Validate Graph environment variables
  try {
    validateGraphEnv();
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Graph Env Validation Error:', error.message);
    logger.error(`Graph Env Validation Error: ${error.message}`);
    return res.status(500).json({ success: false, message: 'Server configuration error for Azure AD operations' });
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
      logger.error(`JSON Parse Error: ${parseError.message}`);
      throw new Error('Invalid user data');
    }
    if (!userData.UserPrincipalName) {
      throw new Error('UserPrincipalName missing');
    }
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Find User Error:', error.message);
    logger.error(`Find User Error: ${error.message}`);
    return res.status(404).json({ success: false, message: 'User not found in Active Directory' });
  }

  const azureUsername = userData.UserPrincipalName;
  const command = `
    $clientId = '${graphConfig.clientId}'
    $tenantId = '${graphConfig.tenantId}'
    $clientSecret = '${graphConfig.clientSecret}'
    $secureClientSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($clientId, $secureClientSecret)
    Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential -ErrorAction Stop
    try {
      Update-MgUser -UserId '${azureUsername}' -PasswordProfile @{ Password = '${newPassword}'; ForceChangePasswordNextSignIn = \$false } -ErrorAction Stop
      'Azure password changed successfully'
    } catch {
      Write-Error "Failed to update user password: \$($_.Exception.Message)"
      exit 1
    }
  `;
  try {
    await execPSGraph(command);
    res.json({ success: true, message: 'Azure AD password changed successfully. Note: This does not affect your on-premises AD password.' });
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Azure Password Change Error:', error.message);
    logger.error(`Azure Password Change Error: ${error.message}`);
    if (error.message.includes('User not found') || error.message.includes('Invalid user')) {
      return res.status(404).json({ success: false, message: 'User not found in Azure AD' });
    }
    await storePendingChange(username, newPassword);
    res.status(500).json({
      success: false,
      message: 'Azure AD password change failed. Will retry later.',
    });
  }
}));

const manageSecretCodeFile = async () => {
  try {
    await initializeSecretCodeFile();
    const data = await fs.readFile(SECRET_CODE_FILE, 'utf8');
    let entries = JSON.parse(data || '[]');
    const now = Date.now();
    const validatedEntries = [];
    const activeEntries = [];

    for (const entry of entries) {
      if (entry.status === 'expired') {
        continue;
      } else if (entry.status === 'validated') {
        validatedEntries.push({
          hash: entry.hash,
          username: entry.username,
          timestamp: entry.timestamp
        });
      } else {
        activeEntries.push(entry);
      }
    }

    await fs.writeFile(SECRET_CODE_FILE, JSON.stringify(activeEntries, null, 2));

    if (validatedEntries.length) {
      await fs.mkdir(path.dirname(VALIDATED_LOG_FILE), { recursive: true });
      const logEntry = validatedEntries.map(e =>
        `${new Date().toISOString()} || ${e.hash} || ${e.username} || ${e.timestamp}`
      ).join('\n') + '\n';
      await fs.appendFile(VALIDATED_LOG_FILE, logEntry);
      logger.info(`Moved ${validatedEntries.length} validated codes to validated_codes.log`);
    }

    return true;
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Manage Secret Code File Error:', error.message);
    logger.error(`Manage Secret Code File Error: ${error.message}`);
    throw new Error('Failed to manage secret code file');
  }
};

app.post('/api/generate-code', verifyJWT, verifyAdmin, asyncHandler(async (req, res) => {
  let { secretCode, username } = req.body;
  secretCode = sanitizeInput(secretCode);
  username = sanitizeInput(username);
  if (!secretCode || !username) {
    return res.status(400).json({ success: false, message: 'Secret code and username are required' });
  }

  if (secretCode.length < 8) {
    return res.status(400).json({ success: false, message: 'Secret code must be at least 8 characters long' });
  }
  if (/\s/.test(secretCode)) {
    return res.status(400).json({ success: false, message: 'Secret code cannot contain spaces' });
  }

  try {
    await manageSecretCodeFile();

    const hashedCode = await bcrypt.hash(secretCode, BCRYPT_COST);
    const now = new Date();
    const formattedDate = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')} ${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;

    const newEntry = {
      hash: hashedCode,
      username,
      timestamp: formattedDate,
      status: 'active'
    };

    const data = await fs.readFile(SECRET_CODE_FILE, 'utf8');
    let entries = JSON.parse(data || '[]');
    entries.push(newEntry);

    await fs.writeFile(SECRET_CODE_FILE, JSON.stringify(entries, null, 2));
    logger.info(`Generated secret code for ${username} at ${formattedDate}`);
    res.json({ success: true, message: 'Secret code generated successfully' });
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Generate Code Error:', error.message);
    logger.error(`Generate Code Error: ${error.message}`);
    res.status(500).json({ success: false, message: 'Failed to generate secret code' });
  }
}));

app.post('/api/reset-password', asyncHandler(async (req, res) => {
  let { username, secretCode } = req.body;
  username = sanitizeInput(username);
  secretCode = sanitizeInput(secretCode);
  if (!username || !secretCode) {
    return res.status(400).json({ success: false, message: 'Username and secret code are required' });
  }

  let foundMatch = false;
  try {
    await manageSecretCodeFile();

    const data = await fs.readFile(SECRET_CODE_FILE, 'utf8');
    let entries = JSON.parse(data || '[]');
    const now = Date.now();

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      if (entry.status === 'expired' || entry.status === 'validated') continue;

      const storedDate = new Date(entry.timestamp);
      if (isNaN(storedDate.getTime())) {
        if (!IS_PRODUCTION) console.warn('Invalid date-time format in entry:', entry);
        logger.warn(`Invalid date-time format in entry: ${JSON.stringify(entry)}`);
        continue;
      }

      const timeDiffMs = now - storedDate.getTime();
      if (timeDiffMs > TWENTY_MINUTES || timeDiffMs < 0) {
        entries[i].status = 'expired';
        logger.info(`Marked as expired: ${entry.username} at ${entry.timestamp}`);
      } else if (entry.username === username) {
        const isMatch = await bcrypt.compare(secretCode, entry.hash);
        if (isMatch) {
          foundMatch = true;
          entries[i].status = 'validated';
        }
      }
    }

    const rateLimitCheck = await checkRateLimit(username, 'reset', req.ip, !foundMatch);
    if (!rateLimitCheck.allowed) {
      return res.status(429).json({ success: false, message: rateLimitCheck.message });
    }

    if (!foundMatch) {
      logger.warn(`Invalid secret code attempt for username: ${username}`);
      return res.status(401).json({ success: false, message: 'Invalid or expired secret code' });
    }

    await fs.writeFile(SECRET_CODE_FILE, JSON.stringify(entries, null, 2));
    logger.info(`Validated secret code for ${username}`);

    const tempToken = jwt.sign(
      { username, displayName: username, isAdmin: false },
      JWT_SECRET,
      { expiresIn: '10m' }
    );

    res.json({
      success: true,
      token: tempToken,
      username,
      displayName: username,
    });
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Reset Password Error:', error.message);
    logger.error(`Reset Password Error: ${error.message}`);
    const rateLimitCheck = await checkRateLimit(username, 'reset', req.ip, true);
    if (!rateLimitCheck.allowed) {
      return res.status(429).json({ success: false, message: rateLimitCheck.message });
    }
    return res.status(500).json({ success: false, message: 'Server error occurred' });
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
    logger.error(`Store Pending Change Error: ${error.message}`);
  }
};

const getPendingChanges = async () => {
  try {
    const data = await fs.readFile(PENDING_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Get Pending Changes Error:', error.message);
    logger.error(`Get Pending Changes Error: ${error.message}`);
    return [];
  }
};

const retryPendingChanges = async () => {
  try {
    const pending = await getPendingChanges();
    if (!pending.length) return;
    const updatedPending = [];
    const now = Date.now();

    for (const { username, newPassword, timestamp, retries = 0 } of pending) {
      if (retries >= MAX_RETRIES || now - timestamp > EXPIRY_HOURS * 60 * 60 * 1000) {
        logger.info(`Expiring change for ${username}: ${retries >= MAX_RETRIES ? 'Max retries reached' : 'Expired'}`);
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
          logger.error(`JSON Parse Error: ${parseError.message}`);
          throw new Error('Invalid user data');
        }
        const azureUsername = userData.UserPrincipalName;
        if (!azureUsername) {
          throw new Error('UserPrincipalName missing');
        }

        validateGraphEnv(); // Validate Graph env variables before proceeding

        const command = `
          $clientId = '${graphConfig.clientId}'
          $tenantId = '${graphConfig.tenantId}'
          $clientSecret = '${graphConfig.clientSecret}'
          $secureClientSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
          $credential = New-Object System.Management.Automation.PSCredential($clientId, $secureClientSecret)
          Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential -ErrorAction Stop
          try {
            Update-MgUser -UserId '${azureUsername}' -PasswordProfile @{ Password = '${sanitizedPassword}'; ForceChangePasswordNextSignIn = \$false } -ErrorAction Stop
            'Azure password changed successfully'
          } catch {
            Write-Error "Failed to update user password: \$($_.Exception.Message)"
            exit 1
          }
        `;
        await execPSGraph(command);
        logger.info(`Retry succeeded for ${sanitizedUsername}`);
      } catch (error) {
        if (!IS_PRODUCTION) console.error(`Retry failed for ${sanitizedUsername}:`, error.message);
        logger.error(`Retry failed for ${sanitizedUsername}: ${error.message}`);
        updatedPending.push({ username: sanitizedUsername, newPassword: sanitizedPassword, timestamp, retries: retries + 1 });
      }
    }
    await fs.writeFile(PENDING_FILE, JSON.stringify(updatedPending, null, 2));
  } catch (error) {
    if (!IS_PRODUCTION) console.error('Retry Pending Changes Error:', error.message);
    logger.error(`Retry Pending Changes Error: ${error.message}`);
  }
};

const startServer = async () => {
  try {
    validateEnv();
    await initializePendingFile();
    await initializeSecretCodeFile();
    await initializeBrutalAttemptFile();
    setInterval(retryPendingChanges, RETRY_INTERVAL);
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT} in ${IS_PRODUCTION ? 'production' : 'development'} mode`);
    });
  } catch (error) {
    console.error('Startup failed:', error.message);
    logger.error(`Startup failed: ${error.message}`);
    process.exit(1);
  }
};

startServer();