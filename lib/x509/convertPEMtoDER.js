const binary = require('../binary');

var convertDERtoPEM = function(cert, callback) {
    var cmd = ['x509 -inform PEM -outform DER'];
    binary.openssl.runCommand({cmd: cmd.join(' '), stdin: cert}, function(err, out) {
        callback(err, {
            command: [out.command + ' -in cert.crt'],
            data: out.stdout
        });
    });
}

module.exports = convertDERtoPEM;