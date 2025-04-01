const bin = require('../binary');
var tmp = require('tmp');
var fs = require('fs');
const common = require('../common');

function addCerts(path, addcerts, callback) {
    if(addcerts) {
        fs.writeFile(path + '/certfile.pem', addcerts, function(err) {
            if(err) {
                callback(err);
            } else {
                callback(false);
            }
        });
    } else {
        callback(false);
    }
}

var sign = function(params, callback) {
    let env = {}
    let password = '_PLAIN_'
    if(params.password) {
        password = params.password;
    }
    let outform = 'PEM'
    if(params.outform) {
        outform = params.outform;
    } else {
        if(params.format) {
            outform = params.format;
        }
    }
    let inform = 'PEM'
    if(params.inform) {
        inform = params.inform;
    } else {
        if(params.format) {
            inform = params.format;
        }
    }
    let binary = true;
    if(params.binary) {
        binary = params.binary;
    }
    let detach = false;
    if(params.detach) {
        detach = params.detach;
    }
    let smimecap = true;
    if(params.smimecap) {
        smimecap = params.smimecap;
    }
    let contenttype = false;
    if(params.contenttype) {
        contenttype = params.contenttype;
    }
    let addcerts = false;
    if(params.addcerts) {
        addcerts = params.addcerts;
    }
    let encoding = null;
    if(params.encoding) {
        encoding = params.encoding;
    }
    tmp.dir({unsafeCleanup: true}, function _tempDirCreated(err, path, cleanupCallback) {
        if(err) {
            callback(err, {
                command: [],
                data: false
            });
        } else {
            fs.writeFile(path + '/encrypted.txt', params.data, encoding, function(err) {
                if(err) {
                    cleanupCallback()
                    callback(err, {
                        command: [],
                        data: false
                    });
                } else {
                    fs.writeFile(path + '/smime.pem', params.cert, function(err) {
                        if(err) {
                            cleanupCallback();
                            callback(err, {
                                command: [],
                                data: false
                            });
                        } else {
                            common.writeIfNotFalsy(path + '/smime.key', params.key, function(err) {
                                if(err) {
                                    cleanupCallback();
                                    callback(err, {
                                        command: [],
                                        data: false
                                    });
                                } else {
                                    addCerts(path, addcerts, function(err) {
                                        if(err) {
                                            cleanupCallback();
                                            callback(err, {
                                                command: [],
                                                data: false
                                            });
                                        } else {
                                            let command = ['cms -sign -in encrypted.txt -signer smime.pem'];
                                            if(params.hasOwnProperty('pkcs11')) {
                                                if(params.pkcs11===false || params.pkcs11===null) {
                                                    //cmd.push('-subj /')
                                                } else {
                                                    password = params.pkcs11.pin;
                                                    // params.options.module = params.pkcs11.modulePath
                                                    command.push('-engine pkcs11 -keyform engine -inkey pkcs11:serial=' + params.pkcs11.serial + ';id=%' + params.pkcs11.objectid + ' -passin stdin' );
                                                    env['PKCS11_MODULE_PATH'] = params.pkcs11.modulePath;
                                                }
                                            } else {
                                                command.push('-inkey smime.key -passin stdin');
                                            }
                                            command.push('-outform ' + outform);
                                            command.push('-inform ' + inform);
                                            if(binary) {
                                                command.push('-binary');
                                            }
                                            if(detach===false) {
                                                command.push('-nodetach');
                                            }
                                            if(smimecap===false) {
                                                command.push('-nosmimecap');
                                            }
                                            if(addcerts) {
                                                command.push('-certfile certfile.pem');
                                            }
                                            if(contenttype) {
                                                command.push('-econtent_type ' + contenttype);
                                            }
                                            bin.openssl.runCommand({cmd: command.join(' '), stdin: password, cwd: path, env: env}, function(err, out) {
                                                //console.log(out);
                                                cleanupCallback();
                                                if(err) {
                                                    callback(err, {
                                                        command: [out.command.replace('-passin stdin', '-passin pass:hidden')],
                                                        data: out.stdout.toString()
                                                    });
                                                } else {
                                                    callback(false, {
                                                        command: [out.command.replace('-passin stdin', '-passin pass:hidden')],
                                                        data: out.stdout.toString()
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

module.exports = sign;