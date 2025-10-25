const binary = require('../binary');

var convertPEMtoDER = function(cert, callback) {
    var cmd = ['x509 -inform PEM -outform DER'];
    let stdin = cert;
    if(!cert) {
        stdin = 'EMPTY';
    }
    binary.openssl.runCommand({cmd: cmd.join(' '), stdin: stdin}, function(err, out) {
        callback(err, {
            command: [out.command + ' -in cert.crt'],
            data: out.stdout
        });
    });
}

module.exports = convertPEMtoDER;