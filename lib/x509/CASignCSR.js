const binary = require('../binary');
const config = require('../config');
const common = require('../common');
const getDistinguishedName = require('./getDistinguishedName');
const parse = require('./parse');
const tmp = require('tmp');
const fs = require('fs');
const moment = require('moment');

var CASignCSR = function(params, callback) {
    //let env = {};
    let password = '_PLAIN_'
    params.options.days = typeof params.options.days !== 'undefined' ? params.options.days : 365;
	//if(params.persistcapath) {
    binary.openssl.getVersion(function(err, version) {
        if(err) {
            callback(err,{
                command: null,
                data: null
            });
            return false;
        } else {
            if(false) {
                tmp.dir({unsafeCleanup: true}, function _tempDirCreated(err, path, cleanupCallback1) {
                    if(err) {
                        callback(err, false);
                    } else {
                        common.writeIfNotFalsy(path + '/ca.key', params.key, function(err) {
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
                                                                var cmd = ['ca -in csr.req -config openssl.cnf -create_serial -policy signing_policy -batch -notext -utf8'];
                                                                if(params.hasOwnProperty('pkcs11')) {
                                                                    if(params.pkcs11===false || params.pkcs11===null) {
                                                                        //cmd.push('-subj /')
                                                                    } else {
                                                                        password = params.pkcs11.pin;
                                                                        params.options.module = params.pkcs11.modulePath
                                                                        if(parseInt(version.substring(0, 1)) >= 3) {
                                                                            cmd.push('-keyfile');
                                                                        } else {
                                                                            cmd.push('-engine pkcs11 -keyform engine -key');
                                                                        }
                                                                        cmd.push('pkcs11:serial=' + params.pkcs11.serial + ';id=%' + params.pkcs11.objectid + ' -passin stdin' );
                                                                    }
                                                                }
                                                                config.generate(params.options, true, osslpath, version, function(err, req) {
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
                                                                                        if(params.options.hasOwnProperty('subject')) {
                                                                                            if(params.options.subject===false || params.options.subject===null) {
                                                                                                cmd.push('-subj /')
                                                                                            } else {
                                                                                                cmd.push('-subj ' + getDistinguishedName(params.options.subject));
                                                                                                //console.log(getDistinguishedName(params.options.subject));
                                                                                            }
                                                                                        }
                                                                                        if(params.options.startdate) {
                                                                                            cmd.push('-startdate ' + moment(params.options.startdate).format('YYYYMMDDHHmmss') + 'Z -enddate ' + moment(params.options.enddate).format('YYYYMMDDHHmmss') + 'Z');
                                                                                        } else {
                                                                                            cmd.push('-days ' + params.options.days);
                                                                                        }
                                                                                        if(params.password) {
                                                                                            //env['PASS'] = params.password;
                                                                                            password = params.password;
                                                                                            cmd.push('-passin stdin');
                                                                                        } else {
                                                                                            //env['PASS'] = '_PLAIN_'
                                                                                            cmd.push('-passin stdin');
                                                                                        }
                                                                                        // console.log(req.join('\r\n'));
                                                                                        // console.log(cmd.join(' '));
                                                                                        binary.openssl.runCommand({ cmd: cmd.join(' '), stdin: password, cwd: osslpath}, function(err, out) {
                                                                                            cleanupCallback1();
                                                                                            if(err) {
                                                                                                callback(err, {
                                                                                                    command: [out.command.replace('-passin stdin', '-passin pass:hidden') + ' -in csr.req'],
                                                                                                    data: out.stdout.toString(),
                                                                                                    files: {
                                                                                                        config: req.join('\r\n')
                                                                                                    }
                                                                                                });
                                                                                            } else {
                                                                                                parse({cert: out.stdout.toString()}, function(err, parsecert) {
                                                                                                    if(err) {
                                                                                                        callback(err, {
                                                                                                            command: [out.command.replace('-passin stdin', '-passin pass:hidden') + ' -in csr.req'],
                                                                                                            data: out.stdout.toString(),
                                                                                                            files: {
                                                                                                                config: req.join('\r\n')
                                                                                                            }
                                                                                                        });
                                                                                                    } else {
                                                                                                        callback(false, {
                                                                                                            command: [out.command.replace('-passin stdin', '-passin pass:hidden') + ' -in csr.req'],
                                                                                                            data: out.stdout.toString(),
                                                                                                            serial: parsecert.data.attributes['Serial Number'].split(':').join('').toUpperCase(),
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
                console.log(params);
                config.generate(params.options, true, false, version, function(err, req) {
                    if(err) {
                        callback(err,{
                            command: null,
                            data: null
                        });
                        return false;
                    } else {
                        tmp.dir({unsafeCleanup: true}, function _tempDirCreated(err, path, cleanupCallback) {
                            if(err) {
                                callback(err, false);
                            } else {
                                common.writeIfNotFalsy(path + '/ca.key', params.key, function(err) {
                                    if(err) {
                                        cleanupCallback();
                                        callback(err, false);
                                    } else {
                                        fs.writeFile(path + '/ca.crt', params.ca, function(err) {
                                            if(err) {
                                                cleanupCallback();
                                                callback(err, false);
                                            } else {
                                                fs.writeFile(path + '/openssl.cnf', req.join('\r\n'), function(err) {
                                                    if(err) {
                                                        cleanupCallback();
                                                        callback(err,{
                                                            command: null,
                                                            data: null
                                                        });
                                                        return false;
                                                    } else {
                                                        fs.writeFile(path + '/csr.req', params.csr, function(err) {
                                                            if(err) {
                                                                cleanupCallback();
                                                                callback(err,{
                                                                    command: null,
                                                                    data: null
                                                                });
                                                                return false;
                                                            } else {
                                                                var cmd = ['x509 -req -in ' + path + '/csr.req -CA ' + path + '/ca.crt -extfile ' + path + '/openssl.cnf -extensions req_ext -nameopt utf8'];
                                                                if(params.options.hash) {
                                                                    cmd.push('-' + params.options.hash);
                                                                }
                                                                if(params.options.startdate) {
                                                                    cmd.push('-startdate ' + moment(params.options.startdate).format('YYYYMMDDHHmmss') + 'Z -enddate ' + moment(params.options.enddate).format('YYYYMMDDHHmmss') + 'Z');
                                                                } else {
                                                                    cmd.push('-days ' + params.options.days);
                                                                }
                                                                if(params.password) {
                                                                    //env['PASS'] = params.password;
                                                                    password = params.password;
                                                                    cmd.push('-passin stdin');
                                                                } else {
                                                                    //env['PASS'] = '_PLAIN_'
                                                                    cmd.push('-passin stdin');
                                                                }
                                                                if(params.hasOwnProperty('pkcs11')) {
                                                                    if(params.pkcs11===false || params.pkcs11===null) {
                                                                        cmd.push('-CAkey ' + path + '/ca.key');
                                                                    } else {
                                                                        if(parseInt(version.substring(0, 1)) >= 3) {
                                                                            cmd.push('-CAkey');
                                                                        } else {
                                                                            cmd.push('-engine pkcs11 -keyform engine -CAkey');
                                                                        }
                                                                        cmd.push('pkcs11:serial=' + params.pkcs11.serial + ';id=%' + params.pkcs11.slotid + ';type=private -passin pass:' + params.pkcs11.pin );
                                                                    }
                                                                } else {
                                                                    cmd.push('-CAkey ' + path + '/ca.key');
                                                                }
                                                                binary.openssl.runCommand({cmd: cmd.join(' '), stdin: password}, function(err, out) {
                                                                    // console.log(cmd.join(' '));
                                                                    // console.log(err);
                                                                    // console.log("cert");
                                                                    // console.log(out.stdout.toString());
                                                                    // console.log("cert");
                                                                    if(err) {
                                                                        callback(err, {
                                                                            command: [out.command.replace(path + '/ca.key', 'ca.key').replace(path + '/csr.req', 'cert.csr').replace(path + '/ca.crt', 'ca.crt').replace(path + '/openssl.cnf', 'certconfig.txt') + ' -out cert.crt'],
                                                                            data: out.stdout.toString(),
                                                                            files: {
                                                                                config: req.join('\r\n')
                                                                            }
                                                                        });
                                                                    } else {
                                                                        parse({cert: out.stdout.toString()}, function(err, parsecert) {
                                                                            if(err) {
                                                                                callback(false, {
                                                                                    command: [out.command.replace(path + '/ca.key', 'ca.key').replace(path + '/csr.req', 'cert.csr').replace(path + '/ca.crt', 'ca.crt').replace(path + '/openssl.cnf', 'certconfig.txt') + ' -out cert.crt'],
                                                                                    data: out.stdout.toString(),
                                                                                    files: {
                                                                                        config: req.join('\r\n')
                                                                                    }
                                                                            });
                                                                            }
                                                                            callback(false, {
                                                                                command: [out.command.replace(path + '/ca.key', 'ca.key').replace(path + '/csr.req', 'cert.csr').replace(path + '/ca.crt', 'ca.crt').replace(path + '/openssl.cnf', 'certconfig.txt') + ' -out cert.crt'],
                                                                                data: out.stdout.toString(),
                                                                                serial: parsecert.data.attributes['Serial Number'].split(':').join('').toUpperCase(),
                                                                                files: {
                                                                                    config: req.join('\r\n')
                                                                                }
                                                                            });
                                                                        });
                                                                    }
                                                                    cleanupCallback();
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
        }
    });
}

module.exports = CASignCSR;