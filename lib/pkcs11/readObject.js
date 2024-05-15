const binary = require('../binary');
const x509 = require('../x509');
const common = require('../common');

const readObject = function(params, callback) {
    let cmd = ['--read-object --type ' + params.type + ' --id=' + params.objectid + ' --slot=' + params.slotid];
    if(params) {
        if(params.modulePath) {
            cmd.push('--module ' + params.modulePath);
        }
    }
    binary.pkcs11Tool.runCommand({cmd: cmd.join(' ')}, function(err, object) {
        if(err) {
            callback(err, false, object.stdout);
        } else {
            //console.log(object.command);
            if(params.type=='cert') {
                x509.convertDERtoPEM(object.stdout, function(err, pem) {
                    callback(err,{
                        command: common.flatten([object.command + ' --output-file cert.der', pem.command]),
                        data: pem.data,
                    });
                });
            } else if(params.type=='pubkey'){
                convertRSADERtoPEM(object.stdout, function(err, pem) {
                    //console.log(cmd.join(' '));
                    if(err) {
                        convertECCDERtoPEM(object.stdout, function(err, pem) {
                            callback(err,{
                                command: common.flatten([object.command + ' --output-file cert.der', pem.command]),
                                data: pem.data,
                            });
                        });
                    } else {
                        callback(err,{
                            command: common.flatten([object.command + ' --output-file cert.der', pem.command]),
                            data: pem.data,
                        });
                    }
                });
            } else {
                callback('unrecogized type', false)
            }
        }
    });
}

module.exports = readObject;