const node_openssl = require('../index.js');
var openssl = new node_openssl({debug: false});

openssl.keypair.listECCCurves(function(err, curves) {
    if(err) {
        console.log(err);
    } else {
        console.log(curves);
    }
});

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
        console.log(ecc.data);
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
        console.log(ecc.data);
        openssl.keypair.convertToPKCS8({key: ecc.data, password: ecckeyoptionb.encryption.password}, function(err, pkcs8) {
            if(err) {
                console.log(err);
            } else {
                console.log(pkcs8.data);
                openssl.keypair.convertECCToPKCS1({key: pkcs8.data, encryption: ecckeyoptionb.encryption}, function(err, pkcs1) {
                    if(err) {
                        console.log(err);
                    } else {
                        console.log(pkcs1.data);
                        openssl.keypair.convertToPKCS8({key: pkcs1.data, password: ecckeyoptionb.encryption.password, decrypt: true}, function(err, pkcs8again) {
                            if(err) {
                                console.log(err);
                            } else {
                                console.log(pkcs8again.data);
                                openssl.keypair.convertECCToPKCS1({key: pkcs8again.data}, function(err, pkcs1again) {
                                    if(err) {
                                        console.log(err);
                                    } else {
                                        console.log(pkcs1again.data);
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