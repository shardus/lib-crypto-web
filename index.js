const nacl = require('tweetnacl');
const blake = require('blakejs');
const { Utils } = require('@shardus/types')
nacl.util = require('tweetnacl-util'); // Utility functions for encoding/decoding

let HASH_KEY;

function _throwUninitErr() {
  throw new Error(
    'Initialize function must be called before using other functions from this library.'
  );
}

// Returns 32-bytes random hex string, otherwise the number of bytes can be specified as an integer
function randomBytes(bytes = 32) {
  if (!Number.isInteger(bytes) || bytes <= 0) {
    throw new TypeError('Bytes must be given as integer greater than zero.');
  }
  return Buffer.from(nacl.randomBytes(bytes)).toString('hex');
}

// Returns the Blake2b hash of the input string, default output type is hex
function hash(input, fmt = 'hex') {
  if (!HASH_KEY) {
    throw new Error('Hash key must be passed to the initialize function before calling hash.');
  }
  if (typeof input !== 'string') {
    throw new TypeError('Input must be a string.');
  }

  let inputBuf = nacl.util.decodeUTF8(input);
  let hashed = blake.blake2b(inputBuf, HASH_KEY, 32); // Keyed BLAKE2b hash

  if (fmt === 'hex') {
    return Buffer.from(hashed).toString('hex');
  } else if (fmt === 'uint8arr') {
    return hashed;
  } else {
    throw new Error('Invalid format type.');
  }
}

// Returns the hash of the provided object as a hex string, takes an optional second parameter to hash an object with the "sign" field
function hashObj(obj, removeSign = false) {
  if (typeof obj !== 'object') {
    throw TypeError('Input must be an object.')
  }
  function performHash(obj) {
    let input = Utils.safeStringify(obj)
    let hashed = hash(input)
    return hashed
  }
  if (removeSign) {
    if (!obj.sign) {
      throw Error(
        'Object must contain a sign field if removeSign is flagged true.'
      )
    }
    let signObj = obj.sign
    delete obj.sign
    let hashed = performHash(obj)
    obj.sign = signObj
    return hashed
  } else {
    return performHash(obj)
  }
}

// Generates and returns {publicKey, secretKey} as hex strings
function generateKeypair() {
  let keypair = nacl.sign.keyPair();
  return {
    publicKey: Buffer.from(keypair.publicKey).toString('hex'),
    secretKey: Buffer.from(keypair.secretKey).toString('hex')
  };
}

// Returns a signature obtained by signing the input hash (hex string) with the secret key (hex string)
function sign(input, sk) {
  if (typeof input !== 'string') {
    throw new TypeError('Input must be a string.');
  }

  let inputBuf = decodeHex(input); // Use the hex decoding helper function
  let skBuf = decodeHex(sk); // Use the hex decoding helper function
  let sig;

  try {
    sig = nacl.sign.detached(inputBuf, skBuf);
  } catch (e) {
    throw new Error('Failed to sign input with provided secret key.');
  }

  // Concatenate the signature and the original message
  let combined = new Uint8Array(sig.length + inputBuf.length);
  combined.set(sig);
  combined.set(inputBuf, sig.length);

  return encodeHex(combined);  // Convert to hex for compatibility with old version
}

// Verifies a signature given the message and public key
function verify(msg, sig, pk) {
  if (typeof msg !== 'string') {
    throw new TypeError('Message must be a string.');
  }

  let sigBuf = decodeHex(sig); // Use hex decoding
  let pkBuf = decodeHex(pk); // Use hex decoding

  // Split the signature from the message (first 64 bytes are the signature)
  const actualSignature = sigBuf.slice(0, nacl.sign.signatureLength); // 64-byte signature
  const originalMessage = sigBuf.slice(nacl.sign.signatureLength); // Rest is the message

  // Recalculate the hash of the message to verify
  let recalculatedMessage = decodeHex(msg); // Decode the input hash

  // Now verify the signature
  let verified = nacl.sign.detached.verify(recalculatedMessage, actualSignature, pkBuf);

  return verified;
}

// Initializes the HASH_KEY for the library (accepts hex-encoded key)
function initialize(key) {
  if (!key) {
    throw new Error('Hash key must be passed to initialize function.');
  }
  try {
    HASH_KEY = Buffer.from(key, 'hex');
    if (HASH_KEY.length !== 32) {
      throw new TypeError('Hash key must be a 32-byte hex string.');
    }
  } catch (e) {
    throw new TypeError('Hash key must be a valid 32-byte hex string.');
  }
}

// Attaches a sign field to the input object, containing a signed version
// of the hash of the object, along with the public key of the signer
function signObj(obj, secretKey, publicKey) {
  if (typeof obj !== 'object') {
    throw new TypeError('Input must be an object.');
  }
  if (typeof secretKey !== 'string') {
    throw new TypeError('Secret key must be a hex string.');
  }
  if (typeof publicKey !== 'string') {
    throw new TypeError('Public key must be a hex string.');
  }

  // Step 1: Hash the object using the hashObj function
  let objStr = Utils.safeStringify(obj);
  let hashed = hash(objStr); // Hash the object and return a hex string

  // Step 2: Sign the hashed object
  let signature = sign(hashed, secretKey); // Sign the hash using the secret key

  // Step 3: Attach the public key and signature to the object in the 'sign' field
  obj.sign = {
    owner: publicKey,
    sig: signature
  };

  return obj;
}

// Returns true if the hash of the object minus the sign field matches the signed message in the sign field
function verifyObj(obj) {
  if (typeof obj !== 'object') {
    throw new TypeError('Input must be an object.');
  }

  // Ensure the sign field contains the owner and signature
  if (!obj.sign || !obj.sign.owner || !obj.sign.sig) {
    throw new Error(
      'Object must contain a sign field with the following data: { owner, sig }'
    );
  }

  if (typeof obj.sign.owner !== 'string') {
    throw new TypeError('Owner must be a public key represented as a hex string.');
  }

  if (typeof obj.sign.sig !== 'string') {
    throw new TypeError('Signature must be a valid signature represented as a hex string.');
  }

  // Step 1: Hash the object excluding the sign field
  let objHash = hashObj(obj, true)
  return verify(objHash, obj.sign.sig, obj.sign.owner)
}

function encodeHex(bytes) {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

function decodeHex(hex) {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex string');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

exports.initialize = initialize;
exports.randomBytes = randomBytes;
exports.hash = hash;
exports.hashObj = hashObj;
exports.generateKeypair = generateKeypair;
exports.sign = sign;
exports.signObj = signObj;
exports.verify = verify;
exports.verifyObj = verifyObj;
