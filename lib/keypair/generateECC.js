const binary = require('../binary');
const convertToPKCS8 = require('./convertToPKCS8');
const common = require('../common');

let generateECC = generateECCPrivateKey = function(options, callback) {
    if(options.hasOwnProperty('curve') == false) {
        options.curve = "prime256v1";
    }
    if(options.hasOwnProperty('format') == false) {
        options.format = "PKCS8";
    }
    let cmd = ['ecparam -name '+ options.curve +' -param_enc named_curve -genkey -noout']
    binary.openssl.runCommand({cmd: cmd.join(' ')}, function(err, out1) {
        if(err) {
            callback(err, false, null);
        } else {
            let env = {};
            if(options.encryption) {
                if(options.encryption.hasOwnProperty('cipher') == false) {
                    options.encryption.cipher = 'des3'
                }
                env['PASS'] = options.encryption.password;
                let cmd = ['ec -'+ options.encryption.cipher +' -passout env:PASS'];
                binary.openssl.runCommand({cmd: cmd.join(' '), stdin: out1.stdout.toString(), env: env}, function(err, out2) {
                    if(err) {
                        callback(err, false);
                    } else {
                        if(options.format=="PKCS8") {
                            convertToPKCS8({key: out1.stdout, password: options.encryption.password}, function(err, out3) {
                                if(err) {
                                    callback(err,{
                                        command: common.flatten([out1.command, out2.command.replace('env:PASS','pass:hidden'), out3.command]),
                                        data: out3.data,
                                    });
                                } else {
                                    callback(false,{
                                        command: common.flatten([out1.command, out2.command.replace('env:PASS','pass:hidden'), out3.command]),
                                        data: out3.data,
                                    });
                                }
                            });
                        } else {
                            callback(false,{
                                command: common.flatten([out1.command, out2.command.replace('env:PASS','pass:hidden')]),
                                data: out2.stdout.toString(),
                            });
                        }
                    }
                });
            } else {
                if(options.format=="PKCS8") {
                    convertToPKCS8({key: out1.stdout}, function(err, out2) {
                        if(err) {
                            callback(err,{
                                command: common.flatten([out1.command, out2.command]),
                                data: out2.data.toString(),
                            });
                        } else {
                            callback(false,{
                                command: common.flatten([out1.command, out2.command]),
                                data: out2.data.toString(),
                            });
                        }
                    });
                } else {
                    callback(false,{
                        command: [out1.command],
                        data: out1.stdout.toString(),
                    });
                }
            }
        }
    });
}

module.exports = generateECC;