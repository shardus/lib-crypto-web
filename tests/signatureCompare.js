const cryptoOld = require('../index.js');
const cryptoNew = require('./browser.js');

(async () => {
  try {
    // Initialize both libraries with the same hash key
    const hashKey = '69fa4195670576c0160d660c3be36556ff8d504725be8a59b5a96509e0c994bc';
    await cryptoOld.initialize(hashKey);
    await cryptoNew.initialize(hashKey);

    // Generate keypair from old version and use it for both
    const keys = cryptoOld.generateKeypair();
    console.log('Keypair (Shared):', keys);

    // Random bytes from both versions
    console.log('Random Bytes (Old):', cryptoOld.randomBytes());
    console.log('Random Bytes (New):', cryptoNew.randomBytes());

    // Hash the same object using both libraries
    const testObj = JSON.parse(`{"type":"register","aliasHash":"582bf415ba205e6da4c8bfc21a1d6077108a4c119362412e6c0190e3fe955c00","from":"5c3b3391766fe940615e5d05bcb27f51a02f51b1b4c71ea527bf1f8cb2189fdd","alias":"thantsintoe","timestamp":1728397032699}`)
    console.log('Hash Object (Old):', cryptoOld.hashObj(testObj));
    console.log('Hash Object (New):', cryptoNew.hashObj(testObj));

    let objectToSignOld = JSON.parse(`{"type":"register","aliasHash":"582bf415ba205e6da4c8bfc21a1d6077108a4c119362412e6c0190e3fe955c00","from":"5c3b3391766fe940615e5d05bcb27f51a02f51b1b4c71ea527bf1f8cb2189fdd","alias":"thantsintoe","timestamp":1728397032699}`)
    // Sign the object using the shared keypair and verify in both libraries
    cryptoOld.signObj(objectToSignOld, keys.secretKey, keys.publicKey);
    console.log('Signed Object (Old):', objectToSignOld);
    console.log('Verify Object (Old):', cryptoOld.verifyObj(objectToSignOld));

    // Ensure the object is re-signed using the same keypair in the new version
    let objectToSignNew = JSON.parse(`{"type":"register","aliasHash":"582bf415ba205e6da4c8bfc21a1d6077108a4c119362412e6c0190e3fe955c00","from":"5c3b3391766fe940615e5d05bcb27f51a02f51b1b4c71ea527bf1f8cb2189fdd","alias":"thantsintoe","timestamp":1728397032699}`)
    cryptoNew.signObj(objectToSignNew, keys.secretKey, keys.publicKey);
    console.log('Signed Object (New):', objectToSignNew);
    console.log('Verify Object (New):', cryptoNew.verifyObj(objectToSignNew));

    console.log(`Old and new version signatures match: ${objectToSignOld.sign.sig === objectToSignNew.sign.sig}`);
  } catch (e) {
    console.log(e);
  }
})();
