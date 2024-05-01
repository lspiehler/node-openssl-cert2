const binary = require('../binary');

const compareKeyandCert = function(params, callback) {
    let cmd = ['x509 -pubkey -noout -outform pem']
    let stdin = params.cert;
    binary.runOpenSSLCommand({cmd: cmd.join(' '), stdin: stdin}, function(err, out) {
        if(err) {
            callback(err, {
                command: [out.command],
                data: out.stdout.toString()
            });
        } else {
            callback(false, {
                command: [out.command],
                data: out.stdout.toString()
            });
        }
    });
}

module.exports = compareKeyandCert;