const binary = require('../binary');
const tmp = require('tmp');
const fs = require('fs');

var getCertFromPKCS12 = function(params, callback) {
    let env = {};
    var cmd = ['pkcs12 -nokeys -clcerts'];
    if(params.password) {
        env['PASS'] = params.password;
        cmd.push('-passin env:PASS');
    } else {
        cmd.push('-passin pass:');
    }
    binary.runOpenSSLCommand({cmd: cmd.join(' '), stdin: params.pkcs12, env: env}, function(err, out) {
        if(err) {
            //console.log(out.command);
            callback(err, {
                command: [out.command.replace('pass env:PASS','pass:hidden') + ' -out cert.pem -in cert.pfx'],
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
                command: [out.command.replace('pass env:PASS','pass:hidden') + ' -out cert.pem -in cert.pfx'],
                data: data.join('\n')
            });
        }
    });
}

module.exports = getCertFromPKCS12;