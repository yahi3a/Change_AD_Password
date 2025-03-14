const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { exec } = require('child_process');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// AD configuration using environment variables only
const adConfig = {
  url: process.env.AD_URL,
  username: process.env.AD_USERNAME,
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

// Log AD config for debugging
console.log('AD Config:', {
  url: adConfig.url,
  username: adConfig.username,
  server: adConfig.server,
  password: adConfig.password ? '[REDACTED]' : undefined,
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password are required.' });
  }
  try {
    console.log('Attempting login for:', username);
    const adUsername = `${username}@dragondoson.vn`;
    console.log('Trying:', adUsername);
    // Use PowerShell to authenticate (simplified for now; could use LDAP if needed)
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

app.post('/api/logout', (req, res) => {
  res.json({ success: true, message: 'Logged out successfully.' });
});

app.post('/api/change-password', (req, res) => {
  const { username, newPassword } = req.body;
  if (!username || !newPassword) {
    return res.status(400).json({ success: false, message: 'Username and new password are required.' });
  }
  console.log('Changing password for:', username);
  const psCommand = `powershell -Command "$cred = New-Object System.Management.Automation.PSCredential('${adConfig.username}', (ConvertTo-SecureString '${adConfig.password}' -AsPlainText -Force)); Set-ADAccountPassword -Identity '${username}' -NewPassword (ConvertTo-SecureString '${newPassword}' -AsPlainText -Force) -Server '${adConfig.server}' -Credential $cred"`;
  exec(psCommand, (err, stdout, stderr) => {
    if (err) {
      console.error('Password Change Error:', stderr || err);
      res.status(500).json({ success: false, message: 'Password change failed. Details: ' + (stderr || err.message) });
    } else {
      console.log('Password Change Output:', stdout);
      res.json({ success: true, message: 'Password changed successfully.' });
    }
  });
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);
});