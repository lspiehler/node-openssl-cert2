const binary = require('../binary');
const prepLabel = require('./prepLabel');
const parseOutput = require('./parseOutput');

const generateKeyPair = function(params, callback) {
    //console.log('called');
    //console.log(params);
    let login;
    if(params.loginType=='User') {
        login = '--login --login-type user --pin ' + params.pin
    } else if(params.loginType=='Security Officer') {
        login = '--login --login-type so --so-pin ' + params.pin
    } else {
        callback('Unrecognized login type', false);
        return;
    }
    let label = prepLabel(params.label);
    let cmd = ['--module ' + params.modulePath + ' --label ' + label + ' ' + login + ' --keypairgen --slot ' + params.slotid + ' --id ' + params.objectid + ' --key-type ' + params.keytype];
    //console.log(cmd.join(' '));
    binary.pkcs11Tool.runCommand({cmd: cmd.join(' ')}, function(err, out) {
        //console.log(out);
        if(err) {
            callback(err,{
                command: [out.command],
                //data: resp.stdout.toString(),
                data: out.stdout.toString()
            });
        } else {
            const lines = out.stdout.toString().split('\n')
            const objects = parseOutput(lines);
            callback(false,{
                command: [out.command],
                data: objects,
            });
            /*var csroptions = {
                module: params.module,
                hash: 'sha512',
                days: 365,
                subject: {
                    countryName: 'US',
                    commonName: [
                        'TEMPORARY CERT FOR KEY IMPORT'
                    ]
                }
            }
            x509.selfSignCSR({options: csroptions, pkcs11: {modulePath: params.modulePath, pin: params.signpin, serial: params.serial, objectid: params.objectid}} , function(err, crt) {
                if(err) {
                    callback(err, false);
                    //console.log(crt);
                } else {
                    //console.log(crt);
                    //callback(false, crt);
                    //console.log(cmd.files.config);
                    params.cert = crt.data;
                    //console.log(crt.data);
                    importCertificate(params, function(err, resp) {
                        if(err) {
                            callback(err,{
                                command: [],
                                data: false,
                            });
                        } else {
                            callback(false,{
                                command: [],
                                //data: resp.stdout.toString(),
                                data: out.stdout.toString()
                            });
                        }
                    });
                }
            });*/
        }
    });
}

module.exports = generateKeyPair;