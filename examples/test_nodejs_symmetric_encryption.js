const node_openssl = require('../index.js');
const crypto = require('crypto');
var openssl = new node_openssl();

const plaintext = "encrypt me";

console.log(openssl.crypto);
let encrypt = openssl.crypto.encrypt(plaintext);
console.log(encrypt);
let decrypt = openssl.crypto.decrypt(encrypt);
console.log(decrypt);