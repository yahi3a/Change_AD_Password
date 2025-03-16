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
const PORT = process.env.PORT || 3001;
const RETRY_INTERVAL = 300000;

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

const execPS = async (command) => {
  try {
    const { stdout, stderr } = await exec(command, { encoding: 'utf8' });
    if (stderr && !stdout) throw new Error(stderr);
    console.log('Raw stdout (before parsing):', stdout); // Debug raw output
    return stdout;
  } catch (error) {
    throw new Error(error.message);
  }
};

const getCredString = (username, password) =>
  `$cred = New-Object System.Management.Automation.PSCredential('${username}', (ConvertTo-SecureString '${password}' -AsPlainText -Force));`;

/*app.post('/api/login', asyncHandler(async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password required' });
  }
  const adUsername = `${username}@dragondoson.vn`;
  const command = `powershell -Command "${getCredString(adUsername, password)} Get-ADUser -Identity '${username}' -Server '${adConfig.server}' -Credential $cred"`;
  await execPS(command);
  res.json({ success: true, username: username.split('@')[0] });
}));
*/

app.post('/api/login', asyncHandler(async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    console.log('Missing username or password:', { username, password });
    return res.status(400).json({ success: false, message: 'Username and password required' });
  }
  const adUsername = `${username}@dragondoson.vn`;
  const command = `powershell -Command "& {[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ${getCredString(adUsername, password)} Get-ADUser -Identity '${username}' -Server '${adConfig.server}' -Credential $cred -Properties DisplayName | Select-Object -Property SamAccountName,DisplayName | ConvertTo-Json -Compress | Out-String}"`;
  try {
    const stdout = await execPS(command);
    console.log('Raw stdout from PowerShell:', stdout); // Log raw output
    const userData = JSON.parse(stdout); // Parse the JSON output from PowerShell
    console.log('Parsed user data:', userData); // Log parsed data

    res.json({ 
      success: true, 
      username: userData.SamAccountName || username, 
      displayName: userData.DisplayName || username
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
  const azureUsername = `${username}@dragondoson.vn`;
  const command = `powershell -Command "${getCredString(adConfig.username, adConfig.password)} Connect-MsolService -Credential $cred; Set-MsolUserPassword -UserPrincipalName '${azureUsername}' -NewPassword '${newPassword}' -ForceChangePassword $false"`;
  try {
    await execPS(command);
    res.json({ success: true, message: 'Azure AD password changed successfully' });
  } catch (error) {
    await storePendingChange(username, newPassword);
    res.status(500).json({
      success: false,
      message: `Azure AD password change failed. Will retry later. Details: ${error.message}`
    });
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

const retryPendingChanges = asyncHandler(async () => {
  const pending = await getPendingChanges();
  if (!pending.length) return;
  console.log('Retrying pending Azure AD changes...');
  const updatedPending = [];
  for (const { username, newPassword } of pending) {
    const azureUsername = `${username}@dragondoson.vn`;
    const command = `powershell -Command "${getCredString(adConfig.username, adConfig.password)} Connect-MsolService -Credential $cred; Set-MsolUserPassword -UserPrincipalName '${azureUsername}' -NewPassword '${newPassword}' -ForceChangePassword $false"`;
    try {
      await execPS(command);
      console.log(`Retry succeeded for ${username}`);
    } catch (error) {
      console.error(`Retry failed for ${username}:`, error.message);
      updatedPending.push({ username, newPassword, timestamp: Date.now() });
    }
  }
  await fs.writeFile(PENDING_FILE, JSON.stringify(updatedPending, null, 2));
});

const startServer = async () => {
  try {
    validateEnv();
    await initializePendingFile();
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