const oldCrypto = require('../old_version.js');  // Old version (libsodium)
const newCrypto = require('../index.js');  // New version (Blake2b + TweetNaCl)
// import * as crypto from '@shardus/crypto-utils'
const serverCrypto = require('@shardus/crypto-utils');

(async () => {
  try {
    // Initialize both versions with the same key for hashing
    const HASH_KEY = '69fa4195670576c0160d660c3be36556ff8d504725be8a59b5a96509e0c994bc';

    await newCrypto.initialize(HASH_KEY);
    await oldCrypto.initialize(HASH_KEY);
    await serverCrypto.init(HASH_KEY);

    // Step 1: Generate keypair using the old version (libsodium)
    const sharedKeypair = oldCrypto.generateKeypair();
    console.log("Generated Keypair (Old Version):", sharedKeypair);

    // Test Object to sign
    const testObj = JSON.parse(`{"type":"register","aliasHash":"582bf415ba205e6da4c8bfc21a1d6077108a4c119362412e6c0190e3fe955c00","from":"5c3b3391766fe940615e5d05bcb27f51a02f51b1b4c71ea527bf1f8cb2189fdd","alias":"thantsintoe","timestamp":1728397032699}`)

    // Step 2: Sign the object using the new version (Blake2b + TweetNaCl)
    newCrypto.signObj(testObj, sharedKeypair.secretKey, sharedKeypair.publicKey);
    console.log("Signed Object (New Version):", testObj);

    // Step 3: Verify the signed object using the old version (libsodium)
    const isValid = oldCrypto.verifyObj(testObj);
    console.log("Verify using Old Version (libsodium):", isValid);

    // Step 4: Verify the signed object using the validator version
    const isValidServer = serverCrypto.verifyObj(testObj);
    console.log("Verify using validator version (libsodium):", isValidServer);

    // Step 5: Verify the signed object using new version
    const isValidNew = newCrypto.verifyObj(testObj);
    console.log("Verify using new version:", isValidNew);
  } catch (e) {
    console.error("Error during testing:", e);
  }
})();
