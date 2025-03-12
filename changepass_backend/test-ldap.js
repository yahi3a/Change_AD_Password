const ldap = require('ldapjs');

const adConfig = {
  url: 'ldap://10.10.2.34:389', // Use ldaps://10.10.2.34:636 if secure LDAP is required
  baseDN: 'dc=vh,dc=geleximco'
};

const testUsernames = [
  'ldap.verify', // Simple username
  'VH\\ldap.verify', // NetBIOS format
  'ldap.verify@vh.geleximco' // UPN format
  // Add more formats if provided by IT (e.g., CN=ldap.verify,OU=Users,DC=vh,DC=geleximco)
];

const password = '^&^geLexiMco060424^&^'; // Your confirmed password

const client = ldap.createClient({
  url: adConfig.url
});

testUsernames.forEach((username) => {
  client.bind(username, password, (err) => {
    if (err) {
      console.error(`LDAP Bind Error for ${username}:`, err);
    } else {
      console.log(`Successfully connected to AD with ${username}`);
      client.unbind((unbindErr) => {
        if (unbindErr) console.error('Unbind Error:', unbindErr);
      });
    }
  });
});