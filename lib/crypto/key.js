const crypto = require('crypto');

let key = null;

module.exports = function() {
    if(key == null) {
        key = crypto.randomBytes(32);
    }
    return key;
}