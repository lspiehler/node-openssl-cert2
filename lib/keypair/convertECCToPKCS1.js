const binary = require('../binary');

let convertECCToPKCS1 = function(options, callback) {
    let cmd = ['ec -inform PEM -outform PEM']
    let env = {};
    if(options.encryption) {
        env = {PASS: options.encryption.password};
        cmd.push('-passin env:PASS');
        if(options.decrypt != true) {
            if(options.encryption.hasOwnProperty('cipher')) {
                cmd.push('-'+ options.encryption.cipher);
            } else {
                cmd.push('-aes-256-cbc');
            }
            cmd.push('-passout env:PASS');
        }
    } else {
        cmd.push('-passin pass:');
    }
    binary.runOpenSSLCommand({cmd: cmd.join(' '), stdin: options.key, env: env}, function(err, out) {
        if(err) {
            callback(err,{
                command: [out.command.replace('env:PASS','pass:hidden') + '-in priv.key'],
                data: out.stdout.toString()
            });
        } else {
            callback(false,{
                command: [out.command.replace('env:PASS','pass:hidden') + '-in priv.key'],
                data: out.stdout.toString()
            });
        }
    });
}

module.exports = convertECCToPKCS1;