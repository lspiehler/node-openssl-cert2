const binary = require('../binary');
const convertToPKCS8 = require('./convertToPKCS8');

let generateECC = generateECCPrivateKey = function(options, callback) {
    if(options.hasOwnProperty('curve') == false) {
        options.curve = "prime256v1";
    }
    if(options.hasOwnProperty('format') == false) {
        options.format = "PKCS8";
    }
    let cmd = ['ecparam -name '+ options.curve +' -param_enc named_curve -genkey -noout']
    binary.runOpenSSLCommand({cmd: cmd.join(' ')}, function(err, out1) {
        if(err) {
            callback(err, false, null);
        } else {
            let env = {};
            if(options.encryption) {
                if(options.encryption.hasOwnProperty('cipher') == false) {
                    options.encryption.cipher = 'des3'
                }
                env = {PASS: options.encryption.password};
                let cmd = ['ec -'+ options.encryption.cipher +' -passout env:PASS'];
                binary.runOpenSSLCommand({cmd: cmd.join(' '), stdin: out1.stdout.toString(), env:{PASS: options.encryption.password}}, function(err, out2) {
                    if(err) {
                        callback(err, false);
                    } else {
                        if(options.format=="PKCS8") {
                            convertToPKCS8({key: out1.stdout, password: options.encryption.password}, function(err, out3) {
                                if(err) {
                                    callback(err,{
                                        command: [out1.command, out2.command.replace('env:PASS','pass:hidden'), out3.command],
                                        stdout: out3.stdout,
                                        stderr: out3.stderr
                                    });
                                } else {
                                    callback(false,{
                                        command: [out1.command, out2.command.replace('env:PASS','pass:hidden'), out3.command],
                                        stdout: out3.stdout,
                                        stderr: out3.stderr
                                    });
                                }
                            });
                        } else {
                            callback(false,{
                                command: [out1.command, out2.command.replace('env:PASS','pass:hidden')],
                                stdout: out2.stdout.toString(),
                                stderr: out2.stderr.toString()
                            });
                        }
                    }
                });
            } else {
                if(options.format=="PKCS8") {
                    convertToPKCS8({key: out1.stdout}, function(err, out2) {
                        if(err) {
                            callback(err,{
                                command: [out1.command, out2.command],
                                stdout: out2.stdout.toString(),
                                stderr: out2.stderr.toString()
                            });
                        } else {
                            callback(false,{
                                command: [out1.command, out2.command],
                                stdout: out2.stdout.toString(),
                                stderr: out2.stderr.toString()
                            });
                        }
                    });
                } else {
                    callback(false,{
                        command: [out1.command],
                        stdout: out1.stdout.toString(),
                        stderr: out1.stderr.toString()
                    });
                }
            }
        }
    });
}

module.exports = generateECC;