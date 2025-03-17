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

app.post('/api/login', asyncHandler(async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    console.log('Missing username or password:', { username, password });
    return res.status(400).json({ success: false, message: 'Username and password required' });
  }

  // Step 1: Use admin credentials to find the user's full UPN
  const findUserCommand = `powershell -Command "& {[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ${getCredString(adConfig.username, adConfig.password)} Get-ADUser -Identity '${username}' -Server '${adConfig.server}' -Credential $cred -Properties UserPrincipalName,DisplayName | Select-Object -Property SamAccountName,UserPrincipalName,DisplayName | ConvertTo-Json -Compress | Out-String}"`;

  try {
    // Find the user and get their UPN
    const findStdout = await execPS(findUserCommand);
    console.log('Raw find stdout:', findStdout); // Debug raw output
    const userData = JSON.parse(findStdout);
    console.log('Found user data:', userData);

    if (!userData.UserPrincipalName) {
      throw new Error('User not found in AD');
    }

    const fullUPN = userData.UserPrincipalName; // e.g., hungnt1@dragonoceandoson.vn

    // Step 2: Validate the user's credentials with their full UPN
    const authCommand = `powershell -Command "& {[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ${getCredString(fullUPN, password)} Get-ADUser -Identity '${username}' -Server '${adConfig.server}' -Credential $cred | Out-String}"`;
    await execPS(authCommand); // This validates the password

    // Step 3: Return the user data
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

app.post('/api/reset-password', asyncHandler(async (req, res) => {
  const { username, secretCode } = req.body;
  if (!username || !secretCode) {
    console.log('Missing username or secret code:', { username, secretCode });
    return res.status(400).json({ success: false, message: 'Username and secret code required' });
  }

  // Read and update the secret code file
  const filePath = path.join(__dirname, '../changepass-app/public/reset_password.code');
  try {
    const fileContent = await fs.readFile(filePath, 'utf8');
    const lines = fileContent.trim().split('\n');
    const currentTime = Date.now();
    const validLines = [];

    let codeValid = false;
    let userData = null;

    // Parse and filter lines
    for (const line of lines) {
      const [storedCode, storedUsername, storedTime] = line.trim().split('||').map(part => part.trim());
      if (!storedCode || !storedUsername || !storedTime) continue; // Skip malformed lines

      const codeTime = parseInt(storedTime, 10);
      const timeDifference = (currentTime - codeTime) / 1000; // Convert to seconds

      if (timeDifference <= 1200) { // 20 minutes = 1200 seconds
        validLines.push(line); // Keep valid lines
        if (
          storedCode === secretCode &&
          storedUsername === username
        ) {
          codeValid = true;
          // Fetch user data with admin credentials
          const findUserCommand = `powershell -Command "& {[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ${getCredString(adConfig.username, adConfig.password)} Get-ADUser -Identity '${username}' -Server '${adConfig.server}' -Credential $cred -Properties UserPrincipalName,DisplayName | Select-Object -Property SamAccountName,UserPrincipalName,DisplayName | ConvertTo-Json -Compress | Out-String}"`;
          const findStdout = await execPS(findUserCommand);
          userData = JSON.parse(findStdout);
          console.log('Found user data for reset:', userData);
        }
      } else {
        console.log('Removed expired entry:', line);
      }
    }

    // Write back only valid lines
    await fs.writeFile(filePath, validLines.join('\n') + (validLines.length > 0 ? '\n' : ''), 'utf8');
    console.log('Updated reset_password.code with valid entries:', validLines);

    if (!codeValid) {
      console.log('Validation failed:', { secretCode, username, validLines });
      return res.status(401).json({ success: false, message: 'Invalid or expired secret code' });
    }

    if (!userData || !userData.UserPrincipalName) {
      throw new Error('User not found in AD');
    }

    res.json({
      success: true,
      username: userData.SamAccountName || username,
      displayName: userData.DisplayName || username
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