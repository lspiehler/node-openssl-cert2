const binary = require('../binary');
const config = require('../config');
var tmp = require('tmp');
var fs = require('fs');

module.exports = function(params, callback) {
    let password = 'fakepassword';
    let key;
    if(!params.key) {
        key = '';
    } else {
        key = params.key;
    }
    config.generate(params.options, false, false, function(err, req) {
        if(err) {
            callback(err,{
                command: null,
                data: null
            });
            return false;
        } else {
            tmp.file(function _tempFileCreated(err, csrpath, fd, cleanupCallback) {
                if (err) throw err;
                fs.writeFile(csrpath, req.join('\r\n'), function(err) {
                    if (err) throw err;
                    var cmd = ['req -new -nodes -config ' + csrpath + ' -nameopt utf8 -utf8 -passin env:PASS'];
                    if(params.hasOwnProperty('pkcs11')) {
                        if(params.pkcs11===false || params.pkcs11===null) {
                            //cmd.push('-key ' + keypath);
                        } else {
                            password = params.pkcs11.pin;
                            cmd.push('-engine pkcs11 -keyform engine -key pkcs11:serial=' + params.pkcs11.serial + ';id=%' + params.pkcs11.slotid);
                        }
                    } else {
                        //cmd.push('-key ' + keypath);
                    }
                    //allows openssl to have a blank subject
                    if(!params.options.subject) {
                        cmd.push('-subj /')
                    }
                    if(params.password) {
                        password = params.password
                    }

                    let env = {
                        PASS: password
                    }
            
                    binary.runOpenSSLCommand({ cmd: cmd.join(' '), stdin: key, env: env }, function(err, out) {
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
                        cleanupCallback();
                    });
                });
            });
        }
    });
}