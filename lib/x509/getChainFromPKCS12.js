//FIX BAG ATTRIBUTES WHEN MULTIPLE CERTS IN CHAIN
const binary = require('../binary');

var normalizeChain = function(chain) {
    //console.log(chain);
    const begin = '-----BEGIN CERTIFICATE-----';
    const end = '-----END CERTIFICATE-----';
    var placeholder = chain.indexOf(begin);
    var certs = [];
    var endoutput = false;
    if(placeholder < 0) {
        endoutput = true;
        //callback('No certificate found in openssl command response', 'No certificate found in openssl command response', 'openssl ' + command);
        return [];
    }
    var shrinkout = chain.substring(placeholder);
    //console.log(shrinkout);
    while(!endoutput) {
        let endofcert = shrinkout.indexOf(end);
        certs.push(shrinkout.substring(0, endofcert) + end);
        shrinkout = shrinkout.substring(endofcert); 
        
        placeholder = shrinkout.indexOf(begin);
        //console.log(placeholder);
        if(placeholder <= 0) {
            endoutput = true;
        } else {
            shrinkout = shrinkout.substring(placeholder);
        }
    }

    return certs;
}

var getChainFromPKCS12 = function(params, callback) {
    let env = {};
    //must include -info because without it openssl returns no stdout or stderr and causes the callback to never get called
    var cmd = ['pkcs12 -nokeys -cacerts'];
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
            let chain = normalizeChain(out.stdout.toString());
            /*let data = [];
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
            }*/
            callback(false, {
                command: [out.command.replace('pass env:PASS','pass:hidden') + ' -out cert.pem -in cert.pfx'],
                data: chain
            });
        }
    });
}

module.exports = getChainFromPKCS12;