const binary = require('../binary');
const config = require('../config');
const getDistinguishedName = require('./getDistinguishedName');
const tmp = require('tmp');
const fs = require('fs');

var CASignCSR = function(params, callback) {
    let env = {};
    params.options.days = typeof params.options.days !== 'undefined' ? params.options.days : 365;
	//if(params.persistcapath) {
    if(true) {
        tmp.dir({unsafeCleanup: true}, function _tempDirCreated(err, path, cleanupCallback1) {
            if(err) {
                callback(err, false);
            } else {
                fs.writeFile(path + '/ca.key', params.key, function(err) {
                    if(err) {
                        cleanupCallback1();
                        callback(err, false);
                    } else {
                        fs.writeFile(path + '/ca.crt', params.ca, function(err) {
                            if(err) {
                                cleanupCallback1();
                                callback(err, false);
                            } else {
                                fs.writeFile(path + '/index.txt', '', function(err) {
                                    if(err) {
                                        cleanupCallback1();
                                        callback(err, false);
                                    } else {
                                        fs.writeFile(path + '/index.txt.attr', 'unique_subject = no', function(err) {
                                            if(err) {
                                                cleanupCallback1();
                                                callback(err, false);
                                            } else {
                                                fs.mkdir(path + '/certs', function(err) {
                                                    if(err) {
                                                        cleanupCallback1();
                                                        callback(err, false);
                                                    } else {
                                                        //console.log(path);
                                                        let osslpath;
                                                        if(path.indexOf('\\') >= 0) {
                                                            osslpath = path.split('\\').join('\\\\')
                                                        } else {
                                                            osslpath = path;
                                                        }
                                                        config.generate(params.options, true, osslpath, function(err, req) {
                                                            if(err) {
                                                                cleanupCallback1();
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
                                                                        fs.writeFile(path + '/csr.req', params.csr, function(err) {
                                                                            if(err) {
                                                                                cleanupCallback1();
                                                                                callback(err,{
                                                                                    command: null,
                                                                                    data: null
                                                                                });
                                                                                return false;
                                                                            } else {
                                                                                var cmd = ['ca -in csr.req -config openssl.cnf -create_serial -policy signing_policy -batch -notext -utf8'];
                                                                                if(params.options.hasOwnProperty('subject')) {
                                                                                    if(params.options.subject===false || params.options.subject===null) {
                                                                                        cmd.push('-subj /')
                                                                                    } else {
                                                                                        cmd.push('-subj ' + getDistinguishedName(params.options.subject));
                                                                                    }
                                                                                }
                                                                                if(params.options.startdate) {
                                                                                    cmd.push('-startdate ' + moment(params.options.startdate).format('YYYYMMDDHHmmss') + 'Z -enddate ' + moment(params.options.enddate).format('YYYYMMDDHHmmss') + 'Z');
                                                                                } else {
                                                                                    cmd.push('-days ' + params.options.days);
                                                                                }
                                                                                if(params.password) {
                                                                                    env['PASS'] = params.password;
                                                                                    cmd.push('-passin env:PASS');
                                                                                } else {
                                                                                    env['PASS'] = '_PLAIN_'
                                                                                    cmd.push('-passin env:PASS');
                                                                                }
                                                                                if(params.hasOwnProperty('pkcs11')) {
                                                                                    if(params.pkcs11===false || params.pkcs11===null) {
                                                                                        //cmd.push('-subj /')
                                                                                    } else {
                                                                                        password = params.pkcs11.pin;
                                                                                        cmd.push('-engine pkcs11 -keyform engine -keyfile pkcs11:serial=' + params.pkcs11.serial + ';id=%' + params.pkcs11.slotid + ' -passin stdin' );
                                                                                    }
                                                                                }
                                                                                binary.runOpenSSLCommand({ cmd: cmd.join(' '), stdin: params.csr, cwd: osslpath, env: env}, function(err, out) {
                                                                                    if(err) {
                                                                                        callback(err, {
                                                                                            command: [out.command.replace('env:PASS', 'pass:hidden') + ' -in csr.req'],
                                                                                            data: out.stdout.toString(),
                                                                                            files: {
                                                                                                config: req.join('\r\n')
                                                                                            }
                                                                                        });
                                                                                        cleanupCallback1();
                                                                                    } else {
                                                                                        fs.readFile(osslpath + '/serial.txt', function(err, serial) {
                                                                                            //console.log(osslpath);
                                                                                            cleanupCallback1();
                                                                                            if(err) {
                                                                                                callback(err, {
                                                                                                    command: [out.command.replace('env:PASS', 'pass:hidden') + ' -in csr.req'],
                                                                                                    data: out.stdout.toString(),
                                                                                                    files: {
                                                                                                        config: req.join('\r\n')
                                                                                                    }
                                                                                                });
                                                                                            } else {
                                                                                                callback(false, {
                                                                                                    command: [out.command.replace('env:PASS', 'pass:hidden') + ' -in csr.req'],
                                                                                                    data: out.stdout.toString(),
                                                                                                    serial: serial.toString().replace('\r\n', '').replace('\n', ''),
                                                                                                    files: {
                                                                                                        config: req.join('\r\n')
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
                        });
                    }
                });
            }
        });
    } else {
        config.generate(params.options, true, false, function(err, req) {
            if(err) {
                callback(err,{
                    command: null,
                    data: null
                });
                return false;
            } else {
                tmp.file(function _tempFileCreated(err, capath, fd, cleanupCallback1) {
                    if (err) throw err;
                    fs.writeFile(capath, params.ca, function(err) {
                        if (err) throw err;
                        tmp.file(function _tempFileCreated(err, keypath, fd, cleanupCallback2) {
                            if (err) throw err;
                            fs.writeFile(keypath, params.key, function(err) {
                                if (err) throw err;
                                tmp.file(function _tempFileCreated(err, csrconfig, fd, cleanupCallback3) {
                                    if (err) throw err;
                                    fs.writeFile(csrconfig, req.join('\r\n'), function(err) {
                                        if (err) throw err;
                                        tmp.tmpName(function _tempNameGenerated(err, serialpath) {
                                            var cmd = ['x509 -req -days ' + params.options.days + ' -CA ' + capath + ' -extfile ' + csrconfig + ' -extensions req_ext -CAserial ' + serialpath + ' -CAcreateserial -nameopt utf8'];
                                            if(params.options.hash) {
                                                cmd.push('-' + params.options.hash);
                                            }
                                            if(params.password) {
                                                env['PASS'] = params.password;
                                                cmd.push('-passin env:PASS');
                                            }
                                            if(params.hasOwnProperty('pkcs11')) {
                                                if(params.pkcs11===false || params.pkcs11===null) {
                                                    cmd.push('-CAkey ' + keypath);
                                                } else {
                                                    cmd.push('-engine pkcs11 -CAkeyform engine -CAkey pkcs11:serial=' + params.pkcs11.serial + ';id=%' + params.pkcs11.slotid + ';type=private -passin pass:' + params.pkcs11.pin );
                                                }
                                            } else {
                                                cmd.push('-CAkey ' + keypath);
                                            }
                                            binary.runOpenSSLCommand({cmd: cmd.join(' '), stdin: params.csr, env: env}, function(err, out) {
                                                if(err) {
                                                    callback(err, out.stdout.toString(), {
                                                        command: [out.command.replace(keypath, 'priv.key').replace(csrpath, 'cert.csr').replace(capath, 'ca.crt').replace(csrconfig, 'certconfig.txt') + ' -out cert.crt'],
                                                        files: {
                                                            config: req.join('\r\n')
                                                        }
                                                    });
                                                } else {
                                                    fs.readFile(serialpath, function(err, serial) {
                                                        
                                                        fs.unlink(serialpath, function(err) {
                                                            //delete temp serial file
                                                        });
                                                        
                                                        callback(false, out.stdout.toString(), {
                                                            command: [out.command.replace(keypath, 'priv.key').replace(csrpath, 'cert.csr').replace(capath, 'ca.crt').replace(csrconfig, 'certconfig.txt') + ' -out cert.crt'],
                                                            serial: serial.toString().replace('\r\n', '').replace('\n', ''),
                                                            files: {
                                                                config: req.join('\r\n')
                                                            }
                                                        });
                                                    });
                                                }
                                                if(params.password) {
                                                    passfile.removeCallback();
                                                }
                                                cleanupCallback1();
                                                cleanupCallback2();
                                                cleanupCallback3();
                                            });
                                        });
                                    });
                                });
                            });
                        });
                    });
                });
            }
        });
    }
}

module.exports = CASignCSR;