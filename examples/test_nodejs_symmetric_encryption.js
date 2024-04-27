const node_openssl = require('../index.js');
const crypto = require('crypto');
var openssl = new node_openssl({binpath: "C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe"});

const plaintext = "encrypt me";

console.log(openssl.crypto);
let encrypt = openssl.crypto.encrypt(plaintext);
console.log(encrypt);
let decrypt = openssl.crypto.decrypt(encrypt);
console.log(decrypt);