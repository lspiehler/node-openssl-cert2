const binary = require('../binary');
const config = require('../config');
const common = require('../common');
const tmp = require('tmp');
const fs = require('fs');

const selfSignCSR = function(params, callback) {
    params.options.days = typeof params.options.days !== 'undefined' ? params.options.days : 365;
    binary.openssl.getVersion(function(err, version) {
        if(err) {
            callback(err,{
                command: null,
                data: null
            });
            return false;
        } else {
            tmp.dir({unsafeCleanup: true}, function _tempDirCreated(err, path, cleanupCallback1) {
                if(err) {
                    callback(err,{
                        command: null,
                        data: null
                    });
                    return false;
                } else {
                    common.writeIfNotFalsy(path + '/priv.key', params.key, function(err) {
                        if(err) {
                            cleanupCallback1();
                            callback(err,{
                                command: null,
                                data: null
                            });
                            return false;
                        } else {
                            var cmd = ['req -x509 -nodes -days ' + params.options.days + ' -config openssl.cnf -in req.csr -extensions req_ext -nameopt utf8 -utf8'];
                            let env = {};
                            let pkcs11 = false;
                            if(params.hasOwnProperty('pkcs11')) {
                                pkcs11 = true;
                                if(params.pkcs11===false || params.pkcs11===null) {
                                    cmd.push('-key priv.key');
                                } else {
                                    params.options.module = params.pkcs11.modulePath
                                    if(parseInt(version.substring(0, 1)) >= 3) {
                                        cmd.push('-key');
                                    } else {
                                        cmd.push('-engine pkcs11 -keyform engine -key');
                                    }
                                    cmd.push('pkcs11:serial=' + params.pkcs11.serial + ';id=%' + params.pkcs11.objectid + ' -passin stdin');
                                }
                            } else {
                                cmd.push('-key priv.key');
                            }
                            let stdin = false;
                            if(!params.csr) {
                                params.csr = '';
                                cmd.push('-new');
                            }
                            if(params.password) {
                                stdin = params.password;
                                cmd.push('-passin stdin');
                            } else if(pkcs11) {
                                stdin = params.pkcs11.pin;
                            } else {
                                stdin = '_PLAIN_'
                                cmd.push('-passin stdin');
                            }
                            common.writeIfNotFalsy(path + '/req.csr', params.csr, function(err) {
                                if(err) {
                                    cleanupCallback1();
                                    callback(err,{
                                        command: null,
                                        data: null
                                    });
                                    return false;
                                } else {
                                    config.generate(params.options, true, false, version, function(err, req) {
                                        if(err) {
                                            callback(err,{
                                                command: null,
                                                data: null
                                            });
                                            return false;
                                        } else {
                                            fs.writeFile(path + '/openssl.cnf', req.join('\r\n'), function(err) {
                                                if(err) {
                                                    cleanupCallback1();
                                                    callback(err,{
                                                        command: null,
                                                        data: null
                                                    });
                                                    return false;
                                                } else {
                                                    // console.log(stdin);
                                                    // console.log(cmd.join(' '));
                                                    // console.log(req.join('\r\n'));
                                                    binary.openssl.runCommand({cmd: cmd.join(' '), env: env, stdin: stdin, cwd: path}, function(err, out) {
                                                        if(err) {
                                                            callback(err, {
                                                                command: [out.command.replace('-passin stdin','-passin pass:hidden') + ' -out cert.crt'],
                                                                data: out.stdout.toString(),
                                                                files: {
                                                                    config: req.join('\r\n')
                                                                }
                                                            });
                                                        } else {
                                                            callback(false, {
                                                                command: [out.command.replace('-passin stdin','-passin pass:hidden') + ' -out cert.crt'],
                                                                data: out.stdout.toString(),
                                                                files: {
                                                                    config: req.join('\r\n')
                                                                }
                                                            });
                                                        }
                                                        cleanupCallback1();
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

module.exports = selfSignCSR;