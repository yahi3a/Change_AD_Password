const express = require('express');
const ActiveDirectory = require('activedirectory2').promiseWrapper;
const cors = require('cors');
const bodyParser = require('body-parser');
const { exec } = require('child_process');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const adConfig = {
  url: 'ldap://10.10.2.34:389',
  baseDN: 'dc=vh,dc=geleximco',
  username: 'VH\\adm-hungnt1',
  password: '253416789!!Abc'
};

const ad = new ActiveDirectory(adConfig);

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    let adUsername = `VH\\${username}`;
    let isAuthenticated = await ad.authenticate(adUsername, password);
    if (!isAuthenticated) {
      adUsername = `${username}@${adConfig.baseDN}`;
      isAuthenticated = await ad.authenticate(adUsername, password);
    }
    if (isAuthenticated) {
      res.json({ success: true, username: username.split('\\')[1] || username.split('@')[0] });
    } else {
      res.status(401).json({ success: false, message: 'Invalid username or password.' });
    }
  } catch (error) {
    console.error('AD Authentication Error:', error);
    res.status(500).json({ success: false, message: 'Authentication failed. Please contact support.' });
  }
});

app.post('/api/logout', (req, res) => {
  res.json({ success: true, message: 'Logged out successfully.' });
});

app.post('/api/change-password', async (req, res) => {
  const { username, newPassword } = req.body;
  try {
    // Use PowerShell to reset the password
    await new Promise((resolve, reject) => {
      const psCommand = `powershell -ExecutionPolicy Bypass -File reset-password.ps1 "${username}" "${newPassword}"`;
      exec(psCommand, (err, stdout, stderr) => {
        if (err) {
          console.error('PowerShell Error:', stderr);
          reject(new Error(stderr || 'Failed to execute PowerShell script'));
        } else {
          console.log('PowerShell Output:', stdout);
          resolve(stdout);
        }
      });
    });

    res.json({ success: true, message: 'Password changed successfully.' });
  } catch (error) {
    console.error('Password Change Error:', error);
    res.status(500).json({ success: false, message: 'Password change failed. Please contact support. Details: ' + error.message });
  }
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);
});