const binary = require('../binary');
const tmp = require('tmp');
const fs = require('fs');
const crl = require('../crl');

const request = function(params, callback) {
    /*let password = '_PLAIN_'
    if(params.password) {
        password = params.password;
    }*/
    let cmd = ['ocsp -reqin request.ocsp -respout response.ocsp -index index.txt -CA ca.pem -rkey ocsp.key -rsigner ocsp.pem -text'];
    if(params.hasOwnProperty('nonce')) {
        if(params.nonce == false) {
            cmd.push('-no_nonce');
        }
    }
    if(params.hasOwnProperty('days')) {
        cmd.push('-ndays ' + params.days);
    } else {
        cmd.push('-ndays 7');
    }
    tmp.dir({unsafeCleanup: true}, function _tempDirCreated(err, path, cleanupCallback) {
        if(err) {
            cleanupCallback();
            callback(err,{
                command: [],
                data: out.stdout,
            });
        } else {
            let indexdb = crl.generateIndex(params.revoked);
            fs.writeFile(path + '/index.txt', indexdb.join('\r\n'), function(err) {
				if(err) {
                    cleanupCallback();
                    callback(err,{
                        command: [],
                        data: out.stdout,
                    });
                } else {fs.writeFile(path + '/request.ocsp', params.request, function(err) {
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
                                    fs.writeFile(path + '/ocsp.pem', params.cert, function(err) {
                                        if(err) {
                                            cleanupCallback();
                                            callback(err,{
                                                command: [],
                                                data: out.stdout,
                                            });
                                        } else {
                                            fs.writeFile(path + '/ocsp.key', params.key, function(err) {
                                                if(err) {
                                                    cleanupCallback();
                                                    callback(err,{
                                                        command: [],
                                                        data: out.stdout,
                                                    });
                                                } else {
                                                    binary.openssl.runCommand({cmd: cmd.join(' '), cwd: path}, function(err, out) {
                                                        if(err) {
                                                            callback(err,{
                                                                command: [out.command],
                                                                data: out.stdout.toString(),
                                                            });
                                                        } else {
                                                            fs.readFile(path + '/response.ocsp', function(err, ocspresp) {
                                                                cleanupCallback();
                                                                if(err) {
                                                                    callback(err,{
                                                                        command: [out.command],
                                                                        data: out.stdout.toString(),
                                                                    });
                                                                } else {
                                                                    callback(false,{
                                                                        command: [out.command],
                                                                        data: ocspresp.toString(),
                                                                        text: out.stdout.toString(),
                                                                        files: {
                                                                            index: indexdb.join('\r\n')
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
                            });
                        }
                    });
                }
            });
        }
    });
}

module.exports = request;