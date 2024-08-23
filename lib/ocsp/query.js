const binary = require('../binary');
const parse = require('../x509/parse');
const tmp = require('tmp');
const fs = require('fs');

var query = function(params, callback) {
    tmp.dir({unsafeCleanup: true}, function _tempDirCreated(err, path, cleanupCallback) {
        if(err) {
            callback(err, {
                command: [],
                data: false
            });
        } else {
            fs.writeFile(path + '/cert.pem', params.cert, function(err) {
                if(err) {
                    cleanupCallback();
                    callback(err, {
                        command: [],
                        data: false
                    });
                } else {
                    fs.writeFile(path + '/issuer.pem', params.cacert, function(err) {
                        if(err) {
                            cleanupCallback();
                            callback(err, {
                                command: [],
                                data: false
                            });
                        } else {
                            var cmd = ['ocsp -'+ params.hash +' -issuer '+ path +'/issuer.pem -cert ' + path + '/cert.pem -header host=' + params.uri.split('/')[2] + ' -url ' + params.uri + ' -text -no_cert_verify -CAfile ' + path + '/issuer.pem'];
                            if(params.hasOwnProperty('nonce')==false) {
                                cmd.push('-no_nonce');
                            }
                            binary.openssl.runCommand({cmd: cmd.join(' ')}, function(ocsperr, out) {
                                //console.log(out);
                                cleanupCallback();
                                if(ocsperr) {
                                    parse({cert: params.cert}, function(err, certinfo, cmd) {
                                        if(err) {
                                            callback(err, false)
                                        } else {
                                            //console.log(certinfo.data)
                                            certinfo.data.base64 = params.cert;
                                            callback(ocsperr, {
                                                command: out.command.replaceAll(path + '/', ''),
                                                ca: params.cacert,
                                                cert: certinfo.data,
                                                uri: params.uri,
                                                data: out.stdout.toString()
                                            });
                                        }
                                    });
                                } else {
                                    parse({cert: params.cert}, function(err, certinfo, cmd) {
                                        if(err) {
                                            callback(err, false)
                                        } else {
                                            //console.log(certinfo.data)
                                            certinfo.data.base64 = params.cert;
                                            callback(ocsperr, {
                                                command: out.command.replaceAll(path + '/', ''),
                                                ca: params.cacert,
                                                cert: certinfo.data,
                                                uri: params.uri,
                                                data: out.stdout.toString()
                                            });
                                        }
                                    });
                                }
                            });
                        }
                    });
                }
            })
        }
    });
}

module.exports = query;