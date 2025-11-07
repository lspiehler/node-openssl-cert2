const binary = require('../binary');
const config = require('../config');
const common = require('../common');
const tmp = require('tmp');
const fs = require('fs');
const generateIndex = require('./generateIndex');

var generate = function(params, callback) {
    let password = '_PLAIN_';
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
                    callback(err, false);
                } else {
                    common.writeIfNotFalsy(path + '/ca.key', params.key || Buffer.from([0x00]), function(err) {
                        if(err) {
                            cleanupCallback1();
                            callback(err, false);
                        } else {
                            fs.writeFile(path + '/ca.crt', params.ca, function(err) {
                                if(err) {
                                    cleanupCallback1();
                                    callback(err, false);
                                } else {
                                    fs.writeFile(path + '/index.txt', params.database, function(err) {
                                        if(err) {
                                            cleanupCallback1();
                                            callback(err, false);
                                        } else {
                                            fs.writeFile(path + '/index.txt.attr', 'unique_subject = no', function(err) {
                                                if(err) {
                                                    cleanupCallback1();
                                                    callback(err, false);
                                                } else {
                                                    let module = false;
                                                    let cmd = ['ca -config config.txt' + ' -gencrl -crldays ' + params.crldays.toString()];
                                                    if(params.hasOwnProperty('pkcs11')) {
                                                        if(params.pkcs11===false || params.pkcs11===null) {
                                                            //cmd.push('-subj /')
                                                        } else {
                                                            password = params.pkcs11.pin;
                                                            module = params.pkcs11.modulePath
                                                            if(parseInt(version.substring(0, 1)) >= 3) {
                                                                cmd.push('-keyfile');
                                                            } else {
                                                                cmd.push('-engine pkcs11 -keyform engine -key');
                                                            }
                                                            // cmd.push('pkcs11:serial=' + params.pkcs11.serial + ';id=%' + params.pkcs11.objectid + ' -passin stdin' );
                                                            cmd.push('pkcs11:' + params.pkcs11.uri + ' -passin stdin');
                                                        }
                                                    }
                                                    const baseconfig = {
                                                        module: module,
                                                        hash: 'sha256',
                                                        subject: {
                                                            countryName: 'US'
                                                        }
                                                    }
                                                    let osslpath;
                                                    if(path.indexOf('\\') >= 0) {
                                                        osslpath = path.split('\\').join('\\\\')
                                                    } else {
                                                        osslpath = path;
                                                    }
                                                    config.generate(baseconfig, true, osslpath, version, function(err, config) {
                                                        if(err) {
                                                            cleanupCallback1();
                                                            callback(err,{
                                                                command: null,
                                                                data: null
                                                            });
                                                            return false;
                                                        } else {
                                                            fs.writeFile(path + '/config.txt', config.join('\r\n'), function(err) {
                                                                if(err) {
                                                                    cleanupCallback1();
                                                                    callback(err, false);
                                                                } else {
                                                                    if(params.password) {
                                                                        //env['PASS'] = params.password;
                                                                        password = params.password;
                                                                        cmd.push('-passin stdin');
                                                                    } else {
                                                                        //env['PASS'] = '_PLAIN_'
                                                                        cmd.push('-passin stdin');
                                                                    }
                                                                    if(params.delta) {
                                                                        cmd.push('-in -gendelta');
                                                                    }
                                                                    if(!password) {
                                                                        password = '_EMPTY_'
                                                                    }
                                                                    binary.openssl.runCommand({ cmd: cmd.join(' '), stdin: password, cwd: path}, function(err, out) {
                                                                        if(err) {
                                                                            callback(err, {
                                                                                command: [out.command.replace('-passin stdin', '-passin pass:hidden')],
                                                                                data: out.stdout.toString(),
                                                                                files: {
                                                                                    config: config.join('\r\n'),
                                                                                    index: params.database
                                                                                }
                                                                            });
                                                                            //console.log(path);
                                                                            cleanupCallback1();
                                                                        } else {
                                                                            callback(false, {
                                                                                command: [out.command.replace('-passin stdin', '-passin pass:hidden')],
                                                                                data: out.stdout.toString(),
                                                                                files: {
                                                                                    config: config.join('\r\n'),
                                                                                    index: params.database
                                                                                }
                                                                            });
                                                                            //console.log(path);
                                                                            cleanupCallback1();
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

module.exports = generate;