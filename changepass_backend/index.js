const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);
const fs = require('fs').promises;
const path = require('path');
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
};

const PENDING_FILE = path.join(__dirname, 'pending-azure-changes.json');
const SECRET_CODE_FILE = path.join(__dirname, 'secrets/reset_password.code'); // Moved to back-end secrets folder
const PORT = process.env.PORT || 3001;
const RETRY_INTERVAL = 300000; // 5 minutes
const TWENTY_MINUTES = 20 * 60 * 1000; // 20 minutes in milliseconds

const asyncHandler = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(error => {
    console.error('Error:', error);
    res.status(500).json({ success: false, message: error.message });
  });

const validateEnv = () => {
  const required = ['AD_URL', 'AD_USERNAME', 'AD_PASSWORD', 'AD_SERVER'];
  const missing = required.filter(key => !process.env[key]);
  if (missing.length) throw new Error(`Missing environment variables: ${missing.join(', ')}`);
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
    await fs.writeFile(SECRET_CODE_FILE, JSON.stringify({ code: 'default123', timestamp: Date.now() }));
  }
};

const execPS = async (command) => {
  try {
    const { stdout, stderr } = await exec(command, { encoding: 'utf8' });
    if (stderr && stderr.includes('ERROR')) {
      throw new Error(stderr);
    }
    console.log('Raw stdout (before parsing):', stdout);
    return stdout;
  } catch (error) {
    throw new Error(error.message);
  }
};

const getCredString = (username, password) =>
  `$cred = New-Object System.Management.Automation.PSCredential('${username}', (ConvertTo-SecureString '${password}' -AsPlainText -Force));`;

app.post('/api/login', asyncHandler(async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    console.log('Missing username or password:', { username, password });
    return res.status(400).json({ success: false, message: 'Username and password required' });
  }

  const findUserCommand = `powershell -Command "& {[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ${getCredString(adConfig.username, adConfig.password)} Get-ADUser -Identity '${username}' -Server '${adConfig.server}' -Credential $cred -Properties UserPrincipalName,DisplayName | Select-Object -Property SamAccountName,UserPrincipalName,DisplayName | ConvertTo-Json -Compress | Out-String}"`;
  try {
    const findStdout = await execPS(findUserCommand);
    const userData = JSON.parse(findStdout);
    console.log('Found огра user data:', userData);
    if (!userData.UserPrincipalName) {
      throw new Error('User not found in AD');
    }
    const fullUPN = userData.UserPrincipalName;

    const authCommand = `powershell -Command "& {[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ${getCredString(fullUPN, password)} Get-ADUser -Identity '${username}' -Server '${adConfig.server}' -Credential $cred | Out-String}"`;
    await execPS(authCommand);

    res.json({
      success: true,
      username: userData.SamAccountName || username,
      displayName: userData.DisplayName || username,
    });
  } catch (error) {
    console.error('Login Error Details:', error.message);
    res.status(401).json({ success: false, message: 'Invalid username or password' });
  }
}));

app.post('/api/logout', (req, res) => {
  res.json({ success: true, message: 'Logged out successfully' });
});

app.post('/api/change-ad-password', asyncHandler(async (req, res) => {
  const { username, newPassword } = req.body;
  if (!username || !newPassword) {
    return res.status(400).json({ success: false, message: 'Username and new password required' });
  }
  const command = `powershell -Command "${getCredString(adConfig.username, adConfig.password)} Set-ADAccountPassword -Identity '${username}' -NewPassword (ConvertTo-SecureString '${newPassword}' -AsPlainText -Force) -Server '${adConfig.server}' -Credential $cred"`;
  await execPS(command);
  res.json({ success: true, message: 'AD password changed successfully' });
}));

app.post('/api/change-azure-password', asyncHandler(async (req, res) => {
  const { username, newPassword } = req.body;
  if (!username || !newPassword) {
    return res.status(400).json({ success: false, message: 'Username and new password required' });
  }

  const findUserCommand = `powershell -Command "& {[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ${getCredString(adConfig.username, adConfig.password)} Get-ADUser -Identity '${username}' -Server '${adConfig.server}' -Credential $cred -Properties UserPrincipalName | Select-Object -Property UserPrincipalName | ConvertTo-Json -Compress | Out-String}"`;
  const findStdout = await execPS(findUserCommand);
  const userData = JSON.parse(findStdout);
  const azureUsername = userData.UserPrincipalName;

  const command = `powershell -Command "${getCredString(adConfig.username, adConfig.password)} Connect-MsolService -Credential $cred; Set-MsolUserPassword -UserPrincipalName '${azureUsername}' -NewPassword '${newPassword}' -ForceChangePassword $false"`;
  try {
    await execPS(command);
    res.json({ success: true, message: 'Azure AD password changed successfully' });
  } catch (error) {
    await storePendingChange(username, newPassword);
    res.status(500).json({
      success: false,
      message: `Azure AD password change failed. Will retry later. Details: ${error.message}`,
    });
  }
}));

app.post('/api/reset-password', asyncHandler(async (req, res) => {
  const { username, secretCode } = req.body;
  if (!username || !secretCode) {
    console.log('Missing username or secret code:', { username, secretCode });
    return res.status(400).json({ success: false, message: 'Username and secret code required' });
  }

  try {
    const data = await fs.readFile(SECRET_CODE_FILE, 'utf8').then(data => JSON.parse(data));
    const storedCode = data.code;
    const timestamp = data.timestamp;
    const now = Date.now();

    if (secretCode !== storedCode || (now - timestamp) > TWENTY_MINUTES) {
      return res.status(401).json({ success: false, message: 'Invalid or expired secret code' });
    }

    const findUserCommand = `powershell -Command "& {[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ${getCredString(adConfig.username, adConfig.password)} Get-ADUser -Identity '${username}' -Server '${adConfig.server}' -Credential $cred -Properties UserPrincipalName,DisplayName | Select-Object -Property SamAccountName,UserPrincipalName,DisplayName | ConvertTo-Json -Compress | Out-String}"`;
    const findStdout = await execPS(findUserCommand);
    const userData = JSON.parse(findStdout);

    if (!userData.UserPrincipalName) {
      throw new Error('User not found in AD');
    }

    res.json({
      success: true,
      username: userData.SamAccountName || username,
      displayName: userData.DisplayName || username,
    });
  } catch (error) {
    console.error('Reset Password Error:', error.message);
    res.status(500).json({ success: false, message: 'Reset failed. Contact IT admin.' });
  }
}));

const storePendingChange = async (username, newPassword) => {
  const pending = await getPendingChanges();
  pending.push({ username, newPassword, timestamp: Date.now() });
  await fs.writeFile(PENDING_FILE, JSON.stringify(pending, null, 2));
};

const getPendingChanges = async () => {
  const data = await fs.readFile(PENDING_FILE, 'utf8');
  return JSON.parse(data);
};

const retryPendingChanges = async () => {
  const pending = await getPendingChanges();
  if (!pending.length) return;
  console.log('Retrying pending Azure AD changes...');
  const updatedPending = [];

  for (const { username, newPassword } of pending) {
    const findUserCommand = `powershell -Command "& {[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ${getCredString(adConfig.username, adConfig.password)} Get-ADUser -Identity '${username}' -Server '${adConfig.server}' -Credential $cred -Properties UserPrincipalName | Select-Object -Property UserPrincipalName | ConvertTo-Json -Compress | Out-String}"`;
    try {
      const findStdout = await execPS(findUserCommand);
      const userData = JSON.parse(findStdout);
      const azureUsername = userData.UserPrincipalName;

      const command = `powershell -Command "${getCredString(adConfig.username, adConfig.password)} Connect-MsolService -Credential $cred; Set-MsolUserPassword -UserPrincipalName '${azureUsername}' -NewPassword '${newPassword}' -ForceChangePassword $false"`;
      await execPS(command);
      console.log(`Retry succeeded for ${username}`);
    } catch (error) {
      console.error(`Retry failed for ${username}:`, error.message);
      updatedPending.push({ username, newPassword, timestamp: Date.now() });
    }
  }
  await fs.writeFile(PENDING_FILE, JSON.stringify(updatedPending, null, 2));
};

const startServer = async () => {
  try {
    validateEnv();
    await initializePendingFile();
    await initializeSecretCodeFile();
    setInterval(retryPendingChanges, RETRY_INTERVAL);
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Startup failed:', error.message);
    process.exit(1);
  }
};

startServer();