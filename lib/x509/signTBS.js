const bin = require('../binary');
var tmp = require('tmp');
var fs = require('fs');
const common = require('../common');

//signs bytes another library built (e.g. node-pki-signer's TBS certificate for a CT final certificate) with a PEM key
//and returns the raw signature value, the bytes that go into the certificate's signature BIT STRING
//hash: 'sha256', 'sha384', ... for RSA (PKCS#1 v1.5) and ECDSA keys; false for keys that sign the data itself
//(Ed25519, Ed448, ML-DSA)
var signTBS = function(params, callback) {
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
                            let command = [];
                            if(hash) {
                                command.push('dgst -' + hash + ' -binary -sign ca.key -passin stdin tbs.der');
                            } else {
                                //dgst can't sign with keys that hash the data themselves
                                command.push('pkeyutl -sign -rawin -inkey ca.key -passin stdin -in tbs.der');
                            }
                            bin.openssl.runCommand({cmd: command.join(' '), stdin: password, cwd: path}, function(err, out) {
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
                        }
                    });
                }
            });
        }
    });
}

module.exports = signTBS;
