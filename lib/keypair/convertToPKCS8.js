const binary = require('../binary');

let convertToPKCS8 = function(params, callback) {
    //console.log(key);
    var cmd = ['pkcs8 -topk8 -inform PEM -outform PEM'];
    if(params.password) {
        cmd.push('-passin env:PASS');// + ' -passout pass:' + encryption.password + ' -' + encryption.cipher);
        if(params.decrypt != true) {
            cmd.push('-passout env:PASS');
        } else {
            cmd.push('-nocrypt');
        }
    } else {
        cmd.push('-nocrypt -passin pass:');
    }
    binary.runOpenSSLCommand({cmd: cmd.join(' '), stdin: params.key, env:{PASS:params.password}}, function(err, out) {
        if(err) {
            callback(err,{
                command: [out.command.replace('env:PASS','pass:hidden') + '-in priv.key'],
                stdout: out.stdout.toString(),
                stderr: out.stderr.toString()
            });
        } else {
            callback(false,{
                command: [out.command.replace('env:PASS','pass:hidden') + '-in priv.key'],
                stdout: out.stdout.toString(),
                stderr: out.stderr.toString()
            });
        }
    });
}

module.exports = convertToPKCS8;