const binary = require('../binary');
const prepLabel = require('./prepLabel');
const x509 = require('../x509');
const parseOutput = require('./parseOutput');
const tmp = require('tmp');
const fs = require('fs');

const importCertificate = function(params, callback) {
    //console.log(params);
    let login;
    if(params.loginType=='User') {
        login = '--login --login-type user --pin ' + params.pin
    } else if(params.loginType=='Security Officer') {
        login = '--login --login-type so --so-pin ' + params.pin
    } else {
        callback('Unrecognized login type',{
            command: [],
            //data: resp.stdout.toString(),
            data: false
        });
        return;
    }
    let label = prepLabel(params.label);
    x509.convertPEMtoDER(params.cert, function(err, der) {
        if(err) {
            callback(false,{
                command: [],
                //data: resp.stdout.toString(),
                data: false
            });
        } else {
            tmp.file(function _tempFileCreated(err, objectpath, fd, cleanupCallback1) {
                if (err) {
                    cleanupCallback1();
                    callback(false,{
                        command: [],
                        //data: resp.stdout.toString(),
                        data: false
                    });
                } else {
                    fs.writeFile(objectpath, der.data, function() {
                        if(err) {
                            cleanupCallback1();
                            callback(false,{
                                command: [],
                                //data: resp.stdout.toString(),
                                data: false
                            });
                        } else {
                            let cmd = ['--label ' + label + ' --module ' + params.modulePath + ' ' + login + ' --slot ' + params.slotid + ' --id ' + params.objectid + ' --write-object ' + objectpath + ' --type cert'];
                            //console.log(cmd.join(' '));
                            //console.log(data);
                            binary.pkcs11Tool.runCommand({cmd: cmd.join(' ')}, function(err, out) {
                                cleanupCallback1();
                                const lines = out.stdout.toString().split('\n')
                                const objects = parseOutput(lines);
                                callback(false,{
                                    command: [out.command],
                                    data: objects,
                                });
                            });
                        }
                    });
                }
            });
        }
    });
}

module.exports = importCertificate;