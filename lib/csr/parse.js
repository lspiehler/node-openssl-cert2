const binary = require('../binary');
const x509 = require('../x509');

const parse = function(params, callback) {
    var cmd = [];
    cmd.push('req -text -noout -nameopt utf8');
    binary.runOpenSSLCommand({cmd: cmd.join(), stdin: params.csr}, function(err, out) {
        if(err) {
            callback(out.stderr,false,cmd.join());
        } else {
            x509.getv3Attributes(out.stdout.toString(), params.csr, function(err, extensions) {
                if(err) {
                    callback(err, false, cmd.join())
                } else {
                    var subject = x509.getSubject(out.stdout.toString());
                    var attrs = x509.getAttributes(out.stdout.toString());
                    var csroptions = {
                        extensions: extensions,
                        subject: subject,
                        attributes: attrs
                    }
                    //callback(false,out.stdout,cmd.join());
                    callback(false,{
                        command: [out.command + " -in request.csr"],
                        data: csroptions
                    });
                }
            });
        }
    });
}

module.exports = parse;