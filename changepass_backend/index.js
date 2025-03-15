const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { exec } = require('child_process');
const fs = require('fs').promises; // For async file operations
const path = require('path');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// AD and Azure AD configuration using the same credentials
const adConfig = {
  url: process.env.AD_URL,
  username: process.env.AD_USERNAME, // e.g., admin@dragondoson.vn
  password: process.env.AD_PASSWORD,
  server: process.env.AD_SERVER,
};

// Validate environment variables
const requiredEnvVars = ['AD_URL', 'AD_USERNAME', 'AD_PASSWORD', 'AD_SERVER'];
const missingVars = requiredEnvVars.filter((varName) => !process.env[varName]);
if (missingVars.length > 0) {
  console.error(`Missing required environment variables: ${missingVars.join(', ')}`);
  process.exit(1);
}

// Log config for debugging
console.log('AD/Azure Config:', {
  url: adConfig.url,
  username: adConfig.username,
  server: adConfig.server,
  password: adConfig.password ? '[REDACTED]' : undefined,
});

// File to store pending Azure AD changes
const PENDING_FILE = path.join(__dirname, 'pending-azure-changes.json');

// Ensure pending file exists
const initializePendingFile = async () => {
  try {
    await fs.access(PENDING_FILE);
  } catch {
    await fs.writeFile(PENDING_FILE, JSON.stringify([]));
  }
};
initializePendingFile();

// Login endpoint (unchanged)
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password are required.' });
  }
  try {
    console.log('Attempting login for:', username);
    const adUsername = `${username}@dragondoson.vn`;
    const psCommand = `powershell -Command "$cred = New-Object System.Management.Automation.PSCredential('${adUsername}', (ConvertTo-SecureString '${password}' -AsPlainText -Force)); Get-ADUser -Identity '${username}' -Server '${adConfig.server}' -Credential $cred"`;
    exec(psCommand, (err) => {
      if (err) {
        console.error('AD Authentication Error:', err);
        res.status(401).json({ success: false, message: 'Invalid username or password.' });
      } else {
        res.json({ success: true, username: username.split('@')[0] });
      }
    });
  } catch (error) {
    console.error('AD Authentication Error:', error);
    res.status(500).json({ success: false, message: 'Authentication failed. Please contact support.' });
  }
});



// Logout endpoint (unchanged)
app.post('/api/logout', (req, res) => {
  res.json({ success: true, message: 'Logged out successfully.' });
});

// AD Password Change API
app.post('/api/change-ad-password', (req, res) => {
  const { username, newPassword } = req.body;
  if (!username || !newPassword) {
    return res.status(400).json({ success: false, message: 'Username and new password are required.' });
  }
  console.log('Changing AD password for:', username);

  const adPsCommand = `powershell -Command "$cred = New-Object System.Management.Automation.PSCredential('${adConfig.username}', (ConvertTo-SecureString '${adConfig.password}' -AsPlainText -Force)); Set-ADAccountPassword -Identity '${username}' -NewPassword (ConvertTo-SecureString '${newPassword}' -AsPlainText -Force) -Server '${adConfig.server}' -Credential $cred"`;

  exec(adPsCommand, (err, stdout, stderr) => {
    if (err) {
      console.error('AD Password Change Error:', stderr || err);
      return res.status(500).json({ success: false, message: 'AD password change failed. Details: ' + (stderr || err.message) });
    }
    console.log('AD Password Change Output:', stdout);
    res.json({ success: true, message: 'AD password changed successfully.' });
  });
});

// Azure AD Password Change API
app.post('/api/change-azure-password', async (req, res) => {
  const { username, newPassword } = req.body;
  if (!username || !newPassword) {
    return res.status(400).json({ success: false, message: 'Username and new password are required.' });
  }
  console.log('Changing Azure AD password for:', username);

  const azureUsername = `${username}@dragondoson.vn`;
  const azurePsCommand = `powershell -Command "$cred = New-Object System.Management.Automation.PSCredential('${adConfig.username}', (ConvertTo-SecureString '${adConfig.password}' -AsPlainText -Force)); Connect-MsolService -Credential $cred; Set-MsolUserPassword -UserPrincipalName '${azureUsername}' -NewPassword '${newPassword}' -ForceChangePassword $false"`;

  exec(azurePsCommand, (err, stdout, stderr) => {
    if (err) {
      console.error('Azure AD Password Change Error:', stderr || err);
      // Store the failed change for retry
      storePendingChange(username, newPassword);
      return res.status(500).json({ success: false, message: 'Azure AD password change failed. It will be retried later. Details: ' + (stderr || err.message) });
    }
    console.log('Azure AD Password Change Output:', stdout);
    res.json({ success: true, message: 'Azure AD password changed successfully.' });
  });
});

// Store pending Azure AD changes
const storePendingChange = async (username, newPassword) => {
  try {
    const pending = JSON.parse(await fs.readFile(PENDING_FILE, 'utf8'));
    pending.push({ username, newPassword, timestamp: Date.now() });
    await fs.writeFile(PENDING_FILE, JSON.stringify(pending, null, 2));
    console.log(`Stored pending Azure AD change for ${username}`);
  } catch (error) {
    console.error('Error storing pending change:', error);
  }
};

// Retry pending Azure AD changes
const retryPendingChanges = async () => {
  try {
    const pending = JSON.parse(await fs.readFile(PENDING_FILE, 'utf8'));
    if (pending.length === 0) return;

    console.log('Retrying pending Azure AD changes...');
    const updatedPending = [];

    for (const { username, newPassword } of pending) {
      const azureUsername = `${username}@dragondoson.vn`;
      const azurePsCommand = `powershell -Command "$cred = New-Object System.Management.Automation.PSCredential('${adConfig.username}', (ConvertTo-SecureString '${adConfig.password}' -AsPlainText -Force)); Connect-MsolService -Credential $cred; Set-MsolUserPassword -UserPrincipalName '${azureUsername}' -NewPassword '${newPassword}' -ForceChangePassword $false"`;

      await new Promise((resolve) => {
        exec(azurePsCommand, (err, stdout, stderr) => {
          if (err) {
            console.error(`Retry failed for ${username}:`, stderr || err);
            updatedPending.push({ username, newPassword, timestamp: Date.now() }); // Keep for next retry
          } else {
            console.log(`Retry succeeded for ${username}:`, stdout);
          }
          resolve();
        });
      });
    }

    // Update the pending file with only failed retries
    await fs.writeFile(PENDING_FILE, JSON.stringify(updatedPending, null, 2));
  } catch (error) {
    console.error('Error retrying pending changes:', error);
  }
};

// Check connectivity and retry every 5 minutes (300,000 ms)
setInterval(retryPendingChanges, 300000);

// Start the server
const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);
});