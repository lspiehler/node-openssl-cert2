const binary = require('../binary');

var convertECCDERtoPEM = function(pubkey, callback) {
    var cmd = ['ec -pubin -pubout -inform DER -outform PEM'];
    let stdin = pubkey;
    if(!pubkey) {
        stdin = 'EMPTY';
    }
    binary.openssl.runCommand({cmd: cmd.join(' '), stdin: stdin}, function(err, out) {
        callback(err, {
            command: [out.command + ' -in rsa.pub'],
            data: out.stdout.toString()
        });
    });
}

module.exports = convertECCDERtoPEM;