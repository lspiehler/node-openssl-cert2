const binary = require('../binary');
var tmp = require('tmp');
var fs = require('fs');

var verify = function(params, callback) {
    let inform = 'PEM'
    if(params.inform) {
        inform = params.inform;
    } else {
        if(params.format) {
            inform = params.format;
        }
    }
    tmp.dir({unsafeCleanup: true}, function _tempDirCreated(err, path, cleanupCallback) {
        if(err) {
            callback(err, {
                command: [],
                data: false
            });
        } else {
            fs.writeFile(path + '/ca.pem', params.ca, function(err) {
                if(err) {
                    cleanupCallback();
                    callback(err, {
                        command: [],
                        data: false
                    });
                } else {
                    let command = ['cms -verify -signer signer.pem -inform PEM -binary -CAfile ca.pem'];
                    command.push('-inform ' + inform);
                    binary.openssl.runCommand({cmd: command.join(' '), stdin: params.data, cwd: path}, function(err, out) {
                        if(err) {
                            cleanupCallback();
                            callback(err, {
                                command: [out.command.replace(path, 'cert.pem') + ' -in data.txt'],
                                data: out.stdout.toString()
                            });
                        } else {
                            fs.readFile(path + '/signer.pem', function(err, signercert) {
                                cleanupCallback();
                                if(err) {
                                    callback(err, {
                                        command: [out.command.replace(path, 'cert.pem') + ' -in data.txt'],
                                        data: out.stdout.toString(),
                                        signercert: false
                                    });
                                } else {
                                    callback(false, {
                                        command: [out.command.replace(path, 'cert.pem') + ' -in data.txt'],
                                        data: out.stdout.toString(),
                                        signercert: signercert.toString()
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

module.exports = verify;