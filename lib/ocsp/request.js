const binary = require('../binary');
const tmp = require('tmp');
const fs = require('fs');

const request = function(params, callback) {
    if(params.hasOwnProperty('hash') == false) {
        params.hash = 'sha256';
    }
    let cmd = ['ocsp -' + params.hash + ' -issuer ca.pem -cert cert.pem -CAfile ca.pem -text'];
    if(params.hasOwnProperty('url')) {
        cmd.push('-header host=' + params.url.split('/')[2] + ' -url ' + params.url);
    } else {
        cmd.push('-reqout req.out');
    }
    tmp.dir({unsafeCleanup: true}, function _tempDirCreated(err, path, cleanupCallback) {
        if(err) {
            cleanupCallback();
            callback(err,{
                command: [],
                data: out.stdout,
            });
        } else {
            fs.writeFile(path + '/cert.pem', params.cert, function(err) {
				if(err) {
                    cleanupCallback();
                    callback(err,{
                        command: [],
                        data: out.stdout,
                    });
                } else {
					fs.writeFile(path + '/ca.pem', params.ca, function(err) {
                        if(err) {
                            cleanupCallback();
                            callback(err,{
                                command: [],
                                data: out.stdout,
                            });
                        } else {
                            binary.openssl.runCommand({cmd: cmd.join(' '), cwd: path}, function(err, out) {
                                if(err) {
                                    cleanupCallback();
                                    callback(err,{
                                        command: [out.command],
                                        data: out.stdout.toString()
                                    });
                                } else {
                                    if(params.hasOwnProperty('url')) {
                                        cleanupCallback();
                                        callback(false,{
                                            command: [out.command],
                                            data: out.stdout.toString(),
                                        });
                                    } else {
                                        fs.readFile(path + '/req.out', function(err, ocspreq) {
                                            cleanupCallback();
                                            if(err) {
                                                callback(err,{
                                                    command: [out.command],
                                                    data: out.stdout.toString(),
                                                });
                                            } else {
                                                callback(false,{
                                                    command: [out.command],
                                                    data: ocspreq,
                                                    text: out.stdout.toString()
                                                });
                                            }
                                        });
                                    }
                                }
                            });
                        }
                    });
                }
            });
        }
    });
}

module.exports = request;