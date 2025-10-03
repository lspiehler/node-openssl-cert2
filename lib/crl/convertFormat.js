const binary = require('../binary');
const tmp = require('tmp');
const fs = require('fs');

var convertFormat = function(params, callback) {
    let outform = 'DER'
    if(params.outform) {
        outform = params.outform;
    } else {
        if(params.format) {
            outform = params.format;
        }
    }
    let inform = 'PEM'
    if(params.inform) {
        inform = params.inform;
    } else {
        if(params.format) {
            inform = params.format;
        }
    }
    var cmd = ['crl'];
    cmd.push('-outform ' + outform);
    cmd.push('-inform ' + inform);
    tmp.file(function _tempFileCreated(err, crlfile, fd, cleanupCallback) {
        if (err) {
            callback(err, false);
        } else {
            fs.writeFile(crlfile, params.crl, function(err) {
                if (err) {
                    callback(err, false);
                    cleanupCallback();
                } else {
                    cmd.push('-in ' + crlfile);
                    binary.openssl.runCommand({cmd: cmd.join(' ')}, function(err, out) {
                        callback(err, {
                            command: [out.command.replace(crlfile, 'crl.crl')],
                            data: out.stdout
                        });
                        cleanupCallback();
                    });
                }
            });
        }
    });
}

module.exports = convertFormat;