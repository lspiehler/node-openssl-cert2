const binary = require('../binary');

let convertPEMToDER = function(params, callback) {
    //console.log(key);
    var cmd = [params.type.toLowerCase() + ' -inform PEM -outform DER'];
    let env = {}
    if(params.password) {
        env['PASS'] = params.password;
        cmd.push('-passin env:PASS');// + ' -passout pass:' + encryption.password + ' -' + encryption.cipher);
        if(params.decrypt != true) {
            cmd.push('-aes-256-cbc -passout env:PASS');
        }
    } else {
        cmd.push('-passin pass:');
    }
    binary.openssl.runCommand({cmd: cmd.join(' '), stdin: params.key, env: env}, function(err, out) {
        if(err) {
            callback(err,{
                command: [out.command.replace('env:PASS','pass:hidden') + '-in priv.key'],
                data: out.stdout,
            });
        } else {
            callback(false,{
                command: [out.command.replace('env:PASS','pass:hidden') + '-in priv.key'],
                data: out.stdout,
            });
        }
    });
}

module.exports = convertPEMToDER;