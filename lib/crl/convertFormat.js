const binary = require('../binary');

var convertFormat = function(params, callback) {
    let outform = 'DER'
    if(params.outform) {
        outform = params.outform;
    } else {
        if(params.format) {
            outform = params.format;
        }
    }
    let inform = 'PEM'
    if(params.inform) {
        inform = params.inform;
    } else {
        if(params.format) {
            inform = params.format;
        }
    }
    var cmd = ['crl'];
    cmd.push('-outform ' + outform);
    cmd.push('-inform ' + inform);
    binary.openssl.runCommand({cmd: cmd.join(' '), stdin: params.crl}, function(err, out) {
        callback(err, {
            command: [out.command + ' -in crl.crl'],
            data: out.stdout
        });
    });
}

module.exports = convertFormat;