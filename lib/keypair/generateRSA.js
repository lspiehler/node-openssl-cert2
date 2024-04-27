const binary = require('../binary');
const convertRSAToPKCS1 = require('./convertRSAToPKCS1');

let generateRSA = function(options, callback) {
    let validoptions = [
        'rsa_keygen_bits',
        'rsa_keygen_primes',
        'rsa_keygen_pubexp',
        'format',
        'encryption'
    ]
    
    let cmd = ['genpkey -outform PEM -algorithm RSA'];
    
    options.rsa_keygen_bits = typeof options.rsa_keygen_bits !== 'undefined' ? options.rsa_keygen_bits : 2048;
    options.rsa_keygen_primes = typeof options.rsa_keygen_primes !== 'undefined' ? options.rsa_keygen_primes : false;
    options.rsa_keygen_pubexp = typeof options.rsa_keygen_pubexp !== 'undefined' ? options.rsa_keygen_pubexp : false;
    options.format = typeof options.format !== 'undefined' ? options.format : 'PKCS8';
    if(options.encryption) {
        options.encryption.password = typeof options.encryption.password !== 'undefined' ? options.encryption.password : 'test123';
        options.encryption.cipher = typeof options.encryption.cipher !== 'undefined' ? options.encryption.cipher : 'des3';
    } else {
        options.encryption = false;
    }
    
    for (var option in options) {
        if(validoptions.indexOf(option) >= 0) {
            if(option=='encryption' && options[option]) {
                cmd.push('-pass stdin -' + options[option].cipher);
            } else if(options[option] && option.indexOf('rsa_keygen_') == 0) {
                cmd.push('-pkeyopt ' + option + ':' + options[option]);
            }
        } else {
            callback('Invalid option ' + option , 'Invalid option ' + option );
            return;
        }
    }

    binary.runOpenSSLCommand({ cmd: cmd.join(' '), stdin: options.encryption.password}, function(err, out1) {
        //console.log(err);
        if(err) {
            callback(err,{
                command: [out1.command.replace('pass stdin','pass:hidden') + ' -out priv.key'],
                stdout: out1.stdout.toString(),
                stderr: out1.stderr.toString()
            });
        } else {
            if (options.format == 'PKCS1' ) {
                convertRSAToPKCS1({key: out1.stdout.toString(), encryption: options.encryption}, function(err, out2) {
                    if(err) {
                        callback(err,{
                            command: [out1.command.replace('pass stdin','pass:hidden'), out2.command],
                            stdout: out2.stdout,
                            stderr: out2.stderr
                        });
                    } else {
                        callback(false,{
                            command: [out1.command.replace('pass stdin','pass:hidden'), out2.command],
                            stdout: out2.stdout,
                            stderr: out2.stderr
                        });
                    }
                });
            } else {
                callback(false,{
                    command: [out1.command.replace('pass stdin','pass:hidden') + ' -out priv.key'],
                    stdout: out1.stdout.toString(),
                    stderr: out1.stderr.toString()
                });
            }
        }
    });
}

module.exports = generateRSA;