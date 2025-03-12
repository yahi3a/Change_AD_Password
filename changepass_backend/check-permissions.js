const ldap = require('ldapjs');

const adConfig = {
  url: 'ldap://10.10.2.34:389', // Using LDAP on port 389 as requested
  baseDN: 'dc=vh,dc=geleximco',
  username: 'VH\\adm-hungnt1', // Replace with the account to test (e.g., adm-hungnt1 or ldap.verify)
  password: '253416789!!Abc' // Replace with the correct password
};

const client = ldap.createClient({
  url: adConfig.url
});

let testUserDN = 'CN=Ezcloud Hai,OU=DOITAC,OU=VHG,OU=Geleximco,DC=vh,DC=geleximco'; // Test user (adjust if needed)

console.log('Starting permission check for account:', adConfig.username);

// Step 1: Test Bind
client.bind(adConfig.username, adConfig.password, (bindErr) => {
  if (bindErr) {
    console.error('Bind Test Failed:', bindErr.message);
    client.unbind();
    return;
  }
  console.log('Bind Test Successful: Account can connect to LDAP server.');

  // Step 2: Test Search
  const searchOpts = {
    filter: '(CN=Ezcloud Hai,OU=DOITAC,OU=VHG,OU=Geleximco,DC=vh,DC=geleximco)',
    scope: 'sub',
    attributes: ['dn', 'sAMAccountName', 'cn']
  };

  client.search(adConfig.baseDN, searchOpts, (searchErr, res) => {
    if (searchErr) {
      console.error('Search Test Failed:', searchErr.message);
      client.unbind();
      return;
    }

    let entriesFound = 0;
    res.on('searchEntry', (entry) => {
      entriesFound++;
      console.log('Search Test Successful - Found Entry:', entry.dn.toString());
    });

    res.on('end', (result) => {
      if (result.status === 0) {
        console.log('Search Test Result: Found', entriesFound, 'entries. Account can search users.');
      } else {
        console.error('Search Test Failed with status:', result.status);
      }

      // Step 3: Test Password Modification
      const newPassword = 'Vanhuong@2025';
      const change = new ldap.Change({
        operation: 'replace',
        modification: {
          type: 'unicodePwd',
          values: [Buffer.from(`"${newPassword}"`, 'utf16le')]
        }
      });

      console.log('Attempting password modification on:', testUserDN);
      client.modify(testUserDN, change, (modifyErr) => {
        if (modifyErr) {
          console.error('Modify Test Failed:', modifyErr.message);
          if (modifyErr.name === 'LDAPError' && modifyErr.code === 53) {
            console.warn('UnwillingToPerformError (Code 53): This could indicate insufficient permissions, secure connection required, or AD policy restriction.');
          }
        } else {
          console.log('Modify Test Successful: Account can reset passwords.');
          // Revert the change if successful (optional)
          const revertChange = new ldap.Change({
            operation: 'replace',
            modification: {
              type: 'unicodePwd',
              values: [Buffer.from('"OriginalPassword"', 'utf16le')] // Replace with the original password if known
            }
          });
          client.modify(testUserDN, revertChange, (revertErr) => {
            if (revertErr) console.error('Revert Failed:', revertErr.message);
            else console.log('Password reverted successfully.');
          });
        }

        client.unbind((unbindErr) => {
          if (unbindErr) console.error('Unbind Error:', unbindErr.message);
          else console.log('Unbind successful. Permission check completed.');
        });
      });
    });

    res.on('error', (error) => {
      console.error('Search Error:', error.message);
      client.unbind();
    });
  });
});