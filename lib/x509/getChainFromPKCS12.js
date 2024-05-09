//FIX BAG ATTRIBUTES WHEN MULTIPLE CERTS IN CHAIN
const binary = require('../binary');

var getChainFromPKCS12 = function(params, callback) {
    let env = {};
    //must include -info because without it openssl returns no stdout or stderr and causes the callback to never get called
    var cmd = ['pkcs12 -nokeys -info -cacerts'];
    if(params.password) {
        env['PASS'] = params.password;
        cmd.push('-passin env:PASS');
    } else {
        cmd.push('-passin pass:');
    }
    binary.runOpenSSLCommand({cmd: cmd.join(' '), stdin: params.pkcs12, env: env, waitforstdout: false}, function(err, out) {
        if(err) {
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

module.exports = getChainFromPKCS12;