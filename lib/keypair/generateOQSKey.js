const binary = require('../binary');

const generateOQSKey = function(params, callback) {
    let cmd = ['genpkey'];
    let validparams = [
        'encryption',
        'algorithm'
    ];

    if(params.encryption) {
        params.encryption.password = typeof params.encryption.password !== 'undefined' ? params.encryption.password : 'test123';
        params.encryption.cipher = typeof params.encryption.cipher !== 'undefined' ? params.encryption.cipher : 'aes256';
    } else {
        params.encryption = false;
    }

    if(!params.algorithm) {
        params.algorithm = 'dilithium2';
    }
    
    for (var option in params) {
        if(validparams.indexOf(option) >= 0) {
            if(option=='encryption' && params[option]) {
                cmd.push('-pass stdin -' + params[option].cipher);
            //} else if(params[option] && option.indexOf('rsa_keygen_') == 0) {
            //    cmd.push('-pkeyopt ' + option + ':' + params[option]);
            } else if(option=='algorithm') {
                cmd.push('-algorithm ' + params[option]);
            }
        } else {
            callback('Invalid option ' + option , 'Invalid option ' + option );
            return;
        }
    }
    binary.openssl.runCommand({ cmd: cmd.join(' '), stdin: params.encryption.password}, function(err, out) {
        //console.log(err);
        if(err) {
            callback(err, {
                command: [out.command.replace('pass stdin','pass:hidden')],
                data: out.stdout.toString()
            });
        } else {
            callback(false, {
                command: [out.command.replace('pass stdin','pass:hidden')],
                data: out.stdout.toString()
            });
        }
    });
}

module.exports = generateOQSKey;