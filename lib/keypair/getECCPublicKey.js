const binary = require('../binary');

const getECCPublicKey = function(params, callback) {
    let env = {}
    let cmd = ['ec -pubout -outform pem']
    if(params.password) {
        env['PASS'] = params.password;
        cmd.push('-passin env:PASS');
    } else {
        env['PASS'] = '_PLAIN_'
        cmd.push('-passin env:PASS');
    }
    let stdin = params.key;
    binary.openssl.runCommand({cmd: cmd.join(' '), env: env, stdin: stdin}, function(err, out) {
        if(err) {
            callback(err, {
                command: [out.command],
                data: out.stdout.toString()
            });
        } else {
            callback(false, {
                command: [out.command],
                data: out.stdout.toString()
            });
        }
    });
}

module.exports = getECCPublicKey;