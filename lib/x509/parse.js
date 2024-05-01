const binary = require('../binary');
const getv3Attributes = require('./getv3Attributes');
const getSubject = require('./getSubject');
const getAttributes = require('./getAttributes');

const parse = function(params, callback) {
    var cmd = [];
    let cert = params.cert;
    if(!params.cert) {
        cert = 'FALSE';
    }
    cmd.push('x509 -text -noout -fingerprint -nameopt utf8');
    binary.runOpenSSLCommand({cmd: cmd.join(), stdin: cert}, function(err, out) {
        //console.log(out.stdout.toString());
        if(err) {
            callback(err,{
                command: [out.command + " -in cert.crt"],
                data: false
            });
        } else {
            getv3Attributes(out.stdout.toString(), params.cert, function(err, extensions) {
                if(err) {
                    callback(err, false, cmd.join())
                } else {
                    var subject = getSubject(out.stdout.toString());
                    var attrs = getAttributes(out.stdout.toString());
                    var cert = {
                        extensions: extensions,
                        subject: subject,
                        attributes: attrs
                    }
                    //callback(false,out.stdout,cmd.join());
                    callback(false,{
                        command: [out.command + " -in cert.crt"],
                        data: cert
                    });
                }
            });
        }
    });
}

module.exports = parse;