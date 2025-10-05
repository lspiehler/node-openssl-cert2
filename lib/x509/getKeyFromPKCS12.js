const binary = require('../binary');

var getKeyFromPKCS12 = function(params, callback) {
    let env = {};
    var cmd = ['pkcs12 -nocerts'];
    if(params.encryption) {
        params.encryption.password = typeof params.encryption.password !== 'undefined' ? params.encryption.password : 'test123';
        params.encryption.cipher = typeof params.encryption.cipher !== 'undefined' ? params.encryption.cipher : 'des3';
    } else {
        params.encryption = false;
    }
    if(params.encryption) {
        env['PASSOUT'] = params.encryption.password;
        cmd.push('-passout env:PASSOUT -' + params.encryption.cipher);
    } else {
        cmd.push('-noenc -passout pass:');
    }
    if(params.password) {
        env['PASSIN'] = params.password;
        cmd.push('-passin env:PASSIN');
    } else {
        cmd.push('-passin pass:');
    }
    if(params.hasOwnProperty('legacy') && params.legacy) {
        cmd.push('-legacy');
    }
    binary.openssl.runCommand({cmd: cmd.join(' '), stdin: params.pkcs12, env: env}, function(err, out) {
        if(err) {
            //console.log(out.command);
            callback(err, {
                command: [out.command.replace('pass env:PASSOUT','pass:hidden').replace('pass env:PASSIN','pass:hidden') + ' -out cert.pem -in cert.pfx'],
                data: out.stdout
            });
        } else {
            let stdout = out.stdout.toString().split('\n');
            let data = [];
            let begin = false;
            for(let i = 0; i < stdout.length; i++) {
                if(begin) {
                    data.push(stdout[i]);
                } else {
                    if(stdout[i].substring(0, 5)=='-----') {
                        data.push(stdout[i]);
                        begin = true;
                    }
                }
            }
            callback(false, {
                command: [out.command.replace('pass env:PASSOUT','pass:hidden').replace('pass env:PASSIN','pass:hidden') + ' -out cert.pem -in cert.pfx'],
                data: data.join('\n')
            });
        }
    });
}

module.exports = getKeyFromPKCS12;