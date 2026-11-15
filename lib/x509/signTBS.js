const bin = require('../binary');
var tmp = require('tmp');
var fs = require('fs');
const common = require('../common');
const config = require('../config');

//signs bytes another library built (e.g. node-pki-signer's TBS certificate for a CT final certificate) with a PEM key
//or a key on a PKCS#11 token and returns the raw signature value, the bytes that go into the certificate's signature
//BIT STRING
//hash: 'sha256', 'sha384', ... for RSA (PKCS#1 v1.5) and ECDSA keys; false for keys that sign the data itself
//(Ed25519, Ed448, ML-DSA)
var signTBS = function(params, callback) {
    let env = {}
    let password = '_PLAIN_'
    if(params.password) {
        password = params.password;
    }
    let hash = false;
    if(params.hash) {
        hash = params.hash;
    }
    tmp.dir({unsafeCleanup: true}, function _tempDirCreated(err, path, cleanupCallback) {
        if(err) {
            callback(err, {
                command: [],
                data: false
            });
        } else {
            fs.writeFile(path + '/tbs.der', params.data, function(err) {
                if(err) {
                    cleanupCallback();
                    callback(err, {
                        command: [],
                        data: false
                    });
                } else {
                    common.writeIfNotFalsy(path + '/ca.key', params.key, function(err) {
                        if(err) {
                            cleanupCallback();
                            callback(err, {
                                command: [],
                                data: false
                            });
                        } else {
                            bin.openssl.getVersion(function(err, version) {
                                if(err) {
                                    cleanupCallback();
                                    callback(err, {
                                        command: [],
                                        data: false
                                    });
                                    return;
                                }
                                let command = [];
                                if(hash) {
                                    command.push('dgst -' + hash + ' -binary');
                                } else {
                                    //dgst can't sign with keys that sign the data themselves
                                    command.push('pkeyutl -sign -rawin');
                                }
                                let keyoption = hash ? '-sign' : '-inkey';
                                let quirks = false;
                                if(params.hasOwnProperty('pkcs11') && params.pkcs11!==false && params.pkcs11!==null) {
                                    password = params.pkcs11.pin;
                                    if(parseInt(version.substring(0, 1)) >= 3) {
                                        //there's no config file here to load the pkcs11 provider, so load it on the command line
                                        command.push('-provider pkcs11 -provider default ' + keyoption);
                                        env['PKCS11_PROVIDER_MODULE'] = params.pkcs11.modulePath;
                                        //SoftHSM crashes at exit on OpenSSL 3.5 without its quirk (config/pkcs11ModuleQuirks.js)
                                        quirks = config.pkcs11ModuleQuirks.providerConfig(params.pkcs11.modulePath);
                                        if(quirks) {
                                            env['OPENSSL_CONF'] = path + '/openssl.cnf';
                                        }
                                    } else {
                                        command.push('-engine pkcs11 -keyform engine ' + keyoption);
                                    }
                                    command.push(params.pkcs11.uri + ' -passin stdin');
                                    env['PKCS11_MODULE_PATH'] = params.pkcs11.modulePath;
                                } else {
                                    command.push(keyoption + ' ca.key -passin stdin');
                                }
                                if(hash) {
                                    command.push('tbs.der');
                                } else {
                                    command.push('-in tbs.der');
                                }
                                if(!password) {
                                    password = '_EMPTY_'
                                }
                                common.writeIfNotFalsy(path + '/openssl.cnf', quirks, function(err) {
                                    if(err) {
                                        cleanupCallback();
                                        callback(err, {
                                            command: [],
                                            data: false
                                        });
                                        return;
                                    }
                                    bin.openssl.runCommand({cmd: command.join(' '), stdin: password, cwd: path, env: env}, function(err, out) {
                                        cleanupCallback();
                                        if(err) {
                                            callback(err, {
                                                command: [out.command.replace('-passin stdin', '-passin pass:hidden')],
                                                data: false
                                            });
                                        } else {
                                            callback(false, {
                                                command: [out.command.replace('-passin stdin', '-passin pass:hidden')],
                                                data: out.stdout
                                            });
                                        }
                                    });
                                });
                            });
                        }
                    });
                }
            });
        }
    });
}

module.exports = signTBS;
