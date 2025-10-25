const binary = require('../binary');

var convertDERtoPEM = function(cert, callback) {
    var cmd = ['x509 -inform DER -outform PEM'];
    let stdin = cert;
    if(!cert) {
        stdin = 'EMPTY';
    }
    binary.openssl.runCommand({cmd: cmd.join(' '), stdin: stdin}, function(err, out) {
        callback(err, {
            command: [out.command + ' -in cert.crt'],
            data: out.stdout.toString()
        });
    });
}

module.exports = convertDERtoPEM;