const binary = require('../binary');
const tmp = require('tmp');
const fs = require('fs');

var createPKCS7 = function(params, callback) {
    tmp.file(function _tempFileCreated(err, certfile, fd, cleanupCallback) {
        if (err) {
            callback(err, false);
        } else {
            fs.writeFile(certfile, params.certs.join('\n'), function(err) {
                if (err) {
                    callback(err, false);
                } else {
                    var cmd = ['crl2pkcs7 -nocrl -certfile ' + certfile + ' -outform ' + params.outform];
                    binary.openssl.runCommand({cmd: cmd.join(' ')}, function(err, out) {
                        cleanupCallback();
                        if(err) {
                            callback(false, {
                                command: [out.command.replace(certfile, 'ca.pem')],
                                data: false
                            });
                        } else {
                            let data = out.stdout;
                            if(params.outform == 'PEM') {
                                data = out.stdout.toString();
                            }
                            callback(false, {
                                command: [out.command.replace(certfile, 'ca.pem')],
                                data: data
                            });
                        }
                    });
                }
            });
        }
    });
}

module.exports = createPKCS7;