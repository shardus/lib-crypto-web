const stringify = require('../utils/stringify')
const { safeJsonParse, safeStringify } = stringify

// Generate test data in Node.js
function generateNodeData() {
    const data = {
        // Generate a random byteArray using crypto
        data: new Uint8Array([1, 2, 3]),
        // Create a large BigInt (similar to what you might use for cryptography)
        nonce: BigInt("0x123456789abcdef123456789abcdef"),
        // Add some normal data too
        timestamp: Date.now(),
        message: "Hello from Node.js!"
    };
    return data;
}

const data = generateNodeData()

const stringified = safeStringify(data)
console.log('Stringified data:', stringified)

const parsed = safeJsonParse(stringified)
console.log('Parsed data:', parsed)