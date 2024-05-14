const binary = require('../binary');

const getOpenSSLCertInfo = function(params, callback) {
    var cmd = [];
    let cert = params.cert;
    if(!params.cert) {
        cert = 'FALSE';
    }
    cmd.push('x509 -text -noout -fingerprint -nameopt utf8');
    binary.openssl.runCommand({cmd: cmd.join(), stdin: cert}, function(err, out) {
        //console.log(out.stdout.toString());
        if(err) {
            callback(err,{
                command: [out.command + " -in cert.crt"],
                data: false
            });
        } else {
            //callback(false,out.stdout,cmd.join());
            callback(false,{
                command: [out.command + " -in cert.crt"],
                data: out.stdout.toString()
            });
        }
    });
}

module.exports = getOpenSSLCertInfo;