const binary = require('../binary');
var tmp = require('tmp');
var fs = require('fs');

var encrypt = function(params, callback) {
    //console.log(params);
    tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback) {
        if (err) {
            callback(err, {
                command: [],
                data: false
            });
        } else {
            fs.writeFile(path, params.cert, function(err) {
                if(err) {
                    cleanupCallback();
                    callback(err, {
                        command: [],
                        data: false
                    });
                } else {
                    let command = 'cms -encrypt -binary -outform PEM -aes256 -recip ' + path;
                    binary.openssl.runCommand({cmd: command, stdin: params.data}, function(err, out) {
                        cleanupCallback();
                        if(err) {
                            callback(err, {
                                command: [out.command.replace(path, 'cert.pem') + ' -in data.txt'],
                                data: out.stdout.toString()
                            });
                        } else {
                            callback(false, {
                                command: [out.command.replace(path, 'cert.pem') + ' -in data.txt'],
                                data: out.stdout.toString()
                            });
                        }
                    });
                }
            });
        }
    });
}

module.exports = encrypt;