const binary = require('../binary');
const config = require('../config');
const tmp = require('tmp');
const fs = require('fs');

module.exports = function(params, callback) {
    let password = 'fakepassword';
    let key;
    if(!params.key) {
        key = '';
    } else {
        key = params.key;
    }
    binary.openssl.getVersion(function(err, version) {
        if(err) {
            callback(err,{
                command: null,
                data: null
            });
            return false;
        } else {
            config.generate(params.options, false, false, version, function(err, req) {
                if(err) {
                    callback(err,{
                        command: null,
                        data: null
                    });
                    return false;
                } else {
                    tmp.file(function _tempFileCreated(err, keypath, fd, cleanupCallback1) {
                        if (err) throw err;
                        fs.writeFile(keypath, key, function(err) {
                            if (err) throw err;
                            tmp.file(function _tempFileCreated(err, csrpath, fd, cleanupCallback2) {
                                if (err) throw err;
                                fs.writeFile(csrpath, req.join('\r\n'), function(err) {
                                    if (err) throw err;
                                    var cmd = ['req -new -noenc -config ' + csrpath + ' -nameopt utf8 -utf8 -passin stdin'];
                                    if(params.hasOwnProperty('pkcs11')) {
                                        if(params.pkcs11===false || params.pkcs11===null) {
                                            cmd.push('-key ' + keypath);
                                        } else {
                                            password = params.pkcs11.pin;
                                            if(parseInt(version.substring(0, 1)) >= 3) {
                                                cmd.push('-key');
                                            } else {
                                                cmd.push('-engine pkcs11 -keyform engine -key');
                                            }
                                            cmd.push('pkcs11:serial=' + params.pkcs11.serial + ';id=%' + params.pkcs11.objectid);
                                        }
                                    } else {
                                        cmd.push('-key ' + keypath);
                                    }
                                    //allows openssl to have a blank subject
                                    if(!params.options.subject) {
                                        cmd.push('-subj /')
                                    }
                                    if(params.password) {
                                        password = params.password
                                    }
                            
                            //console.log(cmd);
                            
                                    binary.openssl.runCommand({ cmd: cmd.join(' '), stdin: password }, function(err, out) {
                                        if(err) {
                                            callback(err,{
                                                command: [out.command.replace(csrpath, 'csrconfig.txt') + ' -out cert.csr -key priv.key'],
                                                data: out.stdout.toString(),
                                                files: {
                                                    config: req.join('\r\n')
                                                }
                                            });
                                        } else {
                                            callback(false,{
                                                command: [out.command.replace(csrpath, 'csrconfig.txt') + ' -out cert.csr -key priv.key'],
                                                data: out.stdout.toString(),
                                                files: {
                                                    config: req.join('\r\n')
                                                }
                                            });
                                        }
                                        cleanupCallback1();
                                        cleanupCallback2();
                                    });
                                });
                            });
                        });
                    });
                }
            });
        }
    });
}