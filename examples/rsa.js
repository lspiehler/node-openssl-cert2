const node_openssl = require('../index.js');
const { decrypt } = require('../lib/crypto/index.js');
var openssl = new node_openssl({debug: false});

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
                openssl.keypair.convertPEMToDER({key: pkcs1.data, type: 'RSA', password: rsaoptionsb.encryption.password}, function(err, der) {
                    if(err) {
                        console.log(err);
                    } else {
                        console.log(der.data);
                        openssl.keypair.convertToPKCS8({key: pkcs1.data, password: rsaoptionsb.encryption.password}, function(err, pkcs8) {
                            if(err) {
                                console.log(err);
                            } else {
                                console.log(pkcs8.data);
                                openssl.keypair.convertPEMToDER({key: pkcs8.data, type: 'RSA', password: rsaoptionsb.encryption.password, decrypt: true}, function(err, der) {
                                    if(err) {
                                        console.log(err);
                                    } else {
                                        console.log(der.data);
                                        openssl.keypair.convertRSAToPKCS1({key: pkcs8.data, encryption: rsaoptionsb.encryption, decrypt: true}, function(err, pkcs1again) {
                                            if(err) {
                                                console.log(err);
                                            } else {
                                                console.log(pkcs1again.data);
                                                openssl.keypair.convertPEMToDER({key: pkcs1again.data, type: 'RSA'}, function(err, der) {
                                                    if(err) {
                                                        console.log(err);
                                                    } else {
                                                        console.log(der.data);
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
                    }
                });
            }
        });
    }
});