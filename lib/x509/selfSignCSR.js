const binary = require('../binary');
const config = require('../config');
const tmp = require('tmp');
const fs = require('fs');

const selfSignCSR = function(params, callback) {
    //console.log(csr);
    let env = {};
    let stdin = false;
    if(!params.csr) {
        params.csr = '';
    } else {
        stdin = params.csr;
    }
    if(!params.key) {
        params.key = '';
    }
    params.options.days = typeof params.options.days !== 'undefined' ? params.options.days : 365;
    config.generate(params.options, true, false, function(err, req) {
        if(err) {
            callback(err,{
                command: null,
                data: null
            });
            return false;
        } else {
            tmp.file(function _tempFileCreated(err, keypath, fd, cleanupCallback1) {
                if (err) throw err;
                fs.writeFile(keypath, params.key, function(err) {
                    if (err) throw err;
                    tmp.file(function _tempFileCreated(err, csrconfig, fd, cleanupCallback2) {
                        if (err) throw err;
                        fs.writeFile(csrconfig, req.join('\r\n'), function(err) {
                            if (err) throw err;
                            var cmd = ['req -x509 -nodes -days ' + params.options.days + ' -config ' + csrconfig + ' -extensions req_ext -nameopt utf8 -utf8'];
                            if(params.hasOwnProperty('pkcs11')) {
                                if(params.pkcs11===false || params.pkcs11===null) {
                                    cmd.push('-key ' + keypath);
                                } else {
                                    env['PASS'] = params.pkcs11.pin;
                                    cmd.push('-engine pkcs11 -keyform engine -key pkcs11:serial=' + params.pkcs11.serial + ';id=%' + params.pkcs11.slotid + ' -passin env:PASS' );
                                }
                            } else {
                                cmd.push('-key ' + keypath);
                            }
                            if(params.password) {
                                env['PASS'] = params.password;
                                cmd.push('-passin env:PASS');
                            } else {
                                env['PASS'] = '_PLAIN_'
                                cmd.push('-passin env:PASS');
                            }
                            if(params.csr) {
                                //cmd.push('-in ' + csrpath);
                            } else {
                                cmd.push('-new');
                            }
                    
                    //console.log(cmd);
                    
                            binary.runOpenSSLCommand({cmd: cmd.join(' '), env: env, stdin: stdin}, function(err, out) {
                                if(err) {
                                    callback(err, {
                                        command: [out.command.replace(keypath, 'priv.key').replace(csrconfig, 'certconfig.txt').replace('env:PASS','pass:hidden') + ' -in request.csr' + ' -out cert.crt'],
                                        data: out.stdout.toString(),
                                        files: {
                                            config: req.join('\r\n')
                                        }
                                    });
                                } else {
                                    callback(false, {
                                        command: [out.command.replace(keypath, 'priv.key').replace(csrconfig, 'certconfig.txt').replace('env:PASS','pass:hidden') + ' -in request.csr' + ' -out cert.crt'],
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

module.exports = selfSignCSR;