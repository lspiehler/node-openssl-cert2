const binary = require('../binary');

let convertRSAToPKCS1 = function(options, callback) {
    binary.getVersion(function(err, version) {
        if(err) {
            callback('Failed to get openssl version: ' + err, {});
        } else {
            let cmd = ['rsa -inform PEM -outform PEM']
            if(version.substring(0, 1) == "3") {
                cmd.push('-traditional');
            }
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
                        command: [out.command.replace('env:PASS','pass:hidden') + ' -in priv.key'],
                        data: out.stdout.toString()
                    });
                } else {
                    callback(false,{
                        command: [out.command.replace('env:PASS','pass:hidden') + ' -in priv.key'],
                        data: out.stdout.toString()
                    });
                }
            });
        }
    });
}

module.exports = convertRSAToPKCS1;