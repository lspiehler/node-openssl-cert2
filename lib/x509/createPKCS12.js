const binary = require('../binary');
const tmp = require('tmp');
const fs = require('fs');

var generatePKCS12 = function(params, callback) {
    let env = {};
    var cmd = ['pkcs12 -export -inkey ' + params.keypath];
    if(params.pkcs12pass) {
        env['PASSOUT'] = params.pkcs12pass;
        cmd.push('-passout env:PASSOUT');
    } else {
        cmd.push('-nodes -passout pass:');
    }
    if(params.keypass) {
        env['PASSIN'] = params.keypass;
        cmd.push('-passin env:PASSIN');
    } else {
        cmd.push('-passin pass:');
    }
    if(params.capath) {
        cmd.push('-certfile ' + params.capath);
    }
    if(params.legacy) {
        cmd.push('-legacy');
    }
    binary.openssl.runCommand({cmd: cmd.join(' '), stdin: params.cert, env: env}, function(err, out) {
        if(err) {
            //console.log(out.command);
            callback(err, {
                command: [out.command.replace(params.keypath, 'priv.key').replace(params.capath, 'ca.crt').replace('env:PASSOUT', 'pass:hidden').replace('env:PASSIN', 'pass:hidden') + ' -out cert.pfx -in cert.crt'],
                data: out.stdout
            });
        } else {
            callback(false, {
                command: [out.command.replace(params.keypath, 'priv.key').replace(params.capath, 'ca.crt').replace('env:PASSOUT', 'pass:hidden').replace('env:PASSIN', 'pass:hidden') + ' -out cert.pfx -in cert.crt'],
                data: out.stdout
            });
        }
    });
}

const createPKCS12 = function(params, callback) {
    let legacy = false;
    if(params.hasOwnProperty('legacy')) {
        legacy = params.legacy;
    }
    tmp.file(function _tempFileCreated(err, keypath, fd, cleanupCallback1) {
        if (err) throw err;
        fs.writeFile(keypath, params.key, function(err) {
            if (err) throw err;
            if(params.ca) {
                tmp.file(function _tempFileCreated(err, capath, fd, cleanupCallback2) {
                    if (err) throw err;
                    fs.writeFile(capath, params.ca, function(err) {
                        if (err) throw err;
                        generatePKCS12({
                            cert: params.cert,
                            keypath: keypath,
                            capath: capath,
                            keypass: params.keypass,
                            pkcs12pass: params.pkcs12pass,
                            legacy: legacy
                        }, function(err, pfx) {
                            if(err) {
                                callback(err, pfx);
                            } else {
                                callback(false, pfx);
                            }
                            cleanupCallback1();
                            cleanupCallback2();
                        });
                    });
                });
            } else {
                generatePKCS12({
                    cert: params.cert,
                    keypath: keypath,
                    keypass: params.keypass,
                    pkcs12pass: params.pkcs12pass,
                    legacy: legacy
                }, function(err, pfx, command) {
                    if(err) {
                        callback(err, pfx);
                    } else {
                        callback(false, pfx);
                    }
                    cleanupCallback1();
                });
            }
        });
    });
}

module.exports = createPKCS12;