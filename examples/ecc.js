const node_openssl = require('../index.js');
var openssl = new node_openssl({debug: false, binpath: "C:/Program Files/OpenSSL-Win64/bin/openssl.exe"});

var ecckeyoptionsa = {
	encryption: {
		password: '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\',
		cipher: 'aes-256-cbc'
	},
	curve: 'prime256v1',
	//rsa_keygen_pubexp: 65537,
	format: 'PKCS8'
}

openssl.keypair.generateECC(ecckeyoptionsa, function(err, ecc) {
    if(err) {
        console.log(err);
    } else {
        console.log(ecc.stdout);
    }
});

var ecckeyoptionb = {
	encryption: {
		password: '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\',
		cipher: 'aes-256-cbc'
	},
	curve: 'prime256v1',
	//rsa_keygen_pubexp: 65537,
	format: 'PKCS1'
}

openssl.keypair.generateECC({format: 'PKCS1'}, function(err, ecc) {
    if(err) {
        console.log(err);
    } else {
        console.log(ecc.stdout);
        openssl.keypair.convertToPKCS8({key: ecc.stdout, password: ecckeyoptionb.encryption.password}, function(err, pkcs8) {
            if(err) {
                console.log(err);
            } else {
                console.log(pkcs8.stdout);
                openssl.keypair.convertECCToPKCS1({key: pkcs8.stdout, encryption: ecckeyoptionb.encryption}, function(err, pkcs1) {
                    if(err) {
                        console.log(err);
                    } else {
                        console.log(pkcs1.stdout);
                        openssl.keypair.convertToPKCS8({key: pkcs1.stdout, password: ecckeyoptionb.encryption.password, decrypt: true}, function(err, pkcs8again) {
                            if(err) {
                                console.log(err);
                            } else {
                                console.log(pkcs8again.stdout);
                                openssl.keypair.convertECCToPKCS1({key: pkcs8again.stdout}, function(err, pkcs1again) {
                                    if(err) {
                                        console.log(err);
                                    } else {
                                        console.log(pkcs1again.stdout);
                                    }
                                });
                            }
                        });
                    }
                });
            }
        });
    }
});