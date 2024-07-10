const binary = require('../binary');

const getOCSPURI = function(cert, callback) {
    let cmd = ['x509 -noout -ocsp_uri -nameopt utf8'];
    let stdin = cert;
    if(!stdin || stdin == "") {
        callback('No certificate was supplied to retrieve the OCSP URI from.', {
            command: false,
            data: false
        });
    } else {
        binary.openssl.runCommand({cmd: cmd.join(' '), stdin: stdin}, function(err, out) {
            var uri = out.stdout.toString().replace('\r\n','').replace('\n','')
            if(err || uri == '') {
                callback('Cannot get OCSP URI from certificate.', {
                    command: [out.command + " -in cert.pem"],
                    data: out.stdout.toString()
                });
            } else {
                callback(false, {
                    command: [out.command + " -in cert.pem"],
                    data: uri
                });
            }
        });
    }
}

module.exports = getOCSPURI;