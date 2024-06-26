const binary = require('../binary');
var tmp = require('tmp');
var fs = require('fs');

var decrypt = function(params, callback) {
    let password = '_PLAIN_'
    if(params.password) {
        password = params.password;
    }
    tmp.dir({unsafeCleanup: true}, function _tempDirCreated(err, path, cleanupCallback) {
        if(err) {
            callback(err, {
                command: [],
                data: false
            });
        } else {
            fs.writeFile(path + '/encrypted.txt', params.data, function(err) {
                if(err) {
                    cleanupCallback();
                    callback(err, {
                        command: [],
                        data: false
                    });
                } else {
                    fs.writeFile(path + '/smime.pem', params.cert, function(err) {
                        if(err) {
                            cleanupCallback();
                            callback(err, {
                                command: [],
                                data: false
                            });
                        } else {
                            fs.writeFile(path + '/smime.key', params.key, function(err) {
                                if(err) {
                                    cleanupCallback();
                                    callback(err, {
                                        command: [],
                                        data: false
                                    });
                                } else {
                                    let command = 'cms -decrypt -inform PEM -binary -in encrypted.txt -recip smime.pem -inkey smime.key -passin stdin'
                                    binary.openssl.runCommand({cmd: command, stdin: password, cwd: path}, function(err, out) {
                                        cleanupCallback();
                                        if(err) {
                                            callback(err, {
                                                command: [out.command.replace('-passin stdin', '-passin pass:hidden')],
                                                data: out.stdout.toString()
                                            });
                                        } else {
                                            callback(false, {
                                                command: [out.command.replace('-passin stdin', '-passin pass:hidden')],
                                                data: out.stdout.toString()
                                            });
                                        }
                                    });
                                }
                            });
                        }
                    });
                }
            });
        }
    });
}

module.exports = decrypt;