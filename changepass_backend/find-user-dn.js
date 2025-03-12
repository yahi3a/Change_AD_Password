const ldap = require('ldapjs');

const adConfig = {
  url: 'ldap://10.10.2.34:389', // Use ldaps://10.10.2.34:636 if secure LDAP is required
  baseDN: 'OU=SERVICES,OU=VHG,OU=Geleximco,dc=vh,dc=geleximco',
  username: 'VH\\ldap.verify',
  password: '^&^geLexiMco060424^&^'
};

const client = ldap.createClient({
  url: adConfig.url
});

let entryCount = 0; // Track the number of entries found

client.bind(adConfig.username, adConfig.password, (err) => {
  if (err) {
    console.error('Bind Error:', err);
    return;
  }

  console.log('Bind successful, starting search...');

  const opts = {
    filter: '(objectClass=user)', // Broad filter to find all users
    scope: 'sub', // Search the entire subtree
    attributes: ['dn', 'sAMAccountName', 'cn', 'distinguishedName', 'objectClass', 'userPrincipalName'] // Specific attributes
  };

  console.log('Searching with baseDN:', adConfig.baseDN, 'and filter:', opts.filter);

  client.search(adConfig.baseDN, opts, (searchErr, res) => {
    if (searchErr) {
      console.error('Search Error:', searchErr);
      return;
    }

    res.on('searchEntry', (entry) => {
      entryCount++;
      console.log('Found Entry - User DN:', entry.dn.toString());
      console.log('Raw Entry:', JSON.stringify(entry, null, 2)); // Log the raw entry object
      console.log('Attributes:', entry.attributes.map(attr => ({
        type: attr.type,
        values: attr.vals
      }))); // Log attributes separately
    });

    res.on('searchReference', (referral) => {
      console.log('Referral:', referral.uris);
    });

    res.on('error', (error) => {
      console.error('Search Error:', error);
    });

    res.on('end', (result) => {
      console.log('Search completed with status:', result.status);
      if (result.status !== 0) {
        console.log('Non-zero status details:', result);
      } else if (entryCount === 0) {
        console.log('Warning: No entries found, possible permission or filter issue.');
      } else {
        console.log(`Found ${entryCount} entries.`);
      }
      client.unbind((unbindErr) => {
        if (unbindErr) console.error('Unbind Error:', unbindErr);
      });
    });
  });
});