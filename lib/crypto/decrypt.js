const crypto = require('crypto');
const key = require('./key');

const decryptSymmetric = (params) => {
    // create a decipher object
    console.log(params);
    const decipher = crypto.createDecipheriv(
        "aes-256-gcm", 
        Buffer.from(key()),
        Buffer.from(params.iv)
    );

    // set the authentication tag for the decipher object
    decipher.setAuthTag(Buffer.from(params.tag));

    // update the decipher object with the base64-encoded ciphertext
    let plaintext = decipher.update(params.ciphertext, 'base64', 'utf8');

    // finalize the decryption process
    plaintext += decipher.final('utf8');

    return plaintext;
}

module.exports = decryptSymmetric;