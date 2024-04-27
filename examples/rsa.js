const node_openssl = require('../index.js');
var openssl = new node_openssl({debug: false, binpath: "C:/Program Files/OpenSSL-Win64/bin/openssl.exe"});

let rsaoptionsa = {
    encryption: {
		password: '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\',
		cipher: 'aes-256-cbc'
	},
    format: "PKCS1"
}

openssl.keypair.generateRSA(rsaoptionsa, function(err, rsa) {
    if(err) {
        console.log(err);
    } else {
        console.log(rsa.data);
    }
});

let rsaoptionsb = {
    encryption: {
		password: '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\',
		cipher: 'aes-256-cbc'
	},
    format: "PKCS1"
}

openssl.keypair.generateRSA({}, function(err, rsa) {
    if(err) {
        console.log(err);
    } else {
        console.log(rsa.data);
        openssl.keypair.convertRSAToPKCS1({key: rsa.data, encryption: rsaoptionsb.encryption}, function(err, pkcs1) {
            if(err) {
                console.log(err);
            } else {
                console.log(pkcs1.data);
                openssl.keypair.convertToPKCS8({key: pkcs1.data, password: rsaoptionsb.encryption.password}, function(err, pkcs8) {
                    if(err) {
                        console.log(err);
                    } else {
                        console.log(pkcs8.data);
                        openssl.keypair.convertRSAToPKCS1({key: pkcs8.data, encryption: rsaoptionsb.encryption, decrypt: true}, function(err, pkcs1again) {
                            if(err) {
                                console.log(err);
                            } else {
                                console.log(pkcs1again.data);
                                openssl.keypair.convertToPKCS8({key: pkcs1again.data}, function(err, pkcs8again) {
                                    if(err) {
                                        console.log(err);
                                    } else {
                                        console.log(pkcs8again.data);
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