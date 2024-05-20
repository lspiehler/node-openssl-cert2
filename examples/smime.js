const node_openssl = require('../index.js');
var openssl = new node_openssl({debug: false});
var moment = require('moment');

var recipcacsroptions = {
	hash: 'sha256',
	days: 240,
	extensions: {
		basicConstraints: {
			critical: true,
			CA: true,
			pathlen: 2
		},
		keyUsage: {
			critical: true,
			usages: [
				'keyCertSign',
				'cRLSign'
			]
		}
	},
	subject: {
		countryName: 'US',
		commonName: [
			'Recipient Root CA'
		]
	}
}

var recipcsroptions = {
    hash: 'sha512',
    startdate: moment.utc(new Date()).add(-5, 'minutes').toDate(),
    enddate: moment.utc(new Date()).add(10, 'minutes').toDate(),
    //startdate: moment(new Date(), "YYYY-MM-DD HH:mm:ss", "America/Chicago").utc().add(-5, 'minutes').toDate(),
    //enddate: moment(new Date(), "YYYY-MM-DD HH:mm:ss", "America/Chicago").utc().add(5, 'minutes').toDate(),
    //days: 600,
    subject: {
        commonName: [
            'Recipient SMIME Cert for Validation'
        ]
    },
    extensions: {
        keyUsage: {
            critical: true,
            usages: [
                'digitalSignature',
                'keyEncipherment',
                'dataEncipherment'
            ]
        },
        extendedKeyUsage: {
            critical: true,
            usages: [
                'emailProtection'
            ]	
        }
    }
}

var sendercacsroptions = {
	hash: 'sha256',
	days: 240,
	extensions: {
		basicConstraints: {
			critical: true,
			CA: true,
			pathlen: 2
		},
		keyUsage: {
			critical: true,
			usages: [
				'keyCertSign',
				'cRLSign'
			]
		}
	},
	subject: {
		countryName: 'US',
		commonName: [
			'Sender Root CA'
		]
	}
}

var sendercsroptions = {
    hash: 'sha512',
    startdate: moment.utc(new Date()).add(-5, 'minutes').toDate(),
    enddate: moment.utc(new Date()).add(10, 'minutes').toDate(),
    //startdate: moment(new Date(), "YYYY-MM-DD HH:mm:ss", "America/Chicago").utc().add(-5, 'minutes').toDate(),
    //enddate: moment(new Date(), "YYYY-MM-DD HH:mm:ss", "America/Chicago").utc().add(5, 'minutes').toDate(),
    //days: 600,
    subject: {
        commonName: [
            'Sender SMIME Cert for Validation'
        ]
    },
    extensions: {
        keyUsage: {
            critical: true,
            usages: [
                'digitalSignature',
                'keyEncipherment',
                'dataEncipherment'
            ]
        },
        extendedKeyUsage: {
            critical: true,
            usages: [
                'emailProtection'
            ]	
        }
    }
}

openssl.keypair.generateRSA({}, function(err, reciprootcarsa) {
    if(err) {
        console.log(err);
    } else {
        console.log(reciprootcarsa.data);
        openssl.csr.create({options: recipcacsroptions, key: reciprootcarsa.data}, function(err, recipcsr) {
            if(err) {
                console.log(err);
            } else {
                console.log(recipcsr.data);
				openssl.x509.selfSignCSR({options: recipcacsroptions, csr: recipcsr.data, key: reciprootcarsa.data}, function(err, reciprootcacert) {
					if(err) {
						console.log(err);
					} else {
                        console.log(reciprootcacert);
                        openssl.keypair.generateRSA({}, function(err, reciprsa) {
                            if(err) {
                                console.log(err);
                            } else {
                                console.log(reciprsa.data);
                                openssl.csr.create({options: recipcsroptions, key: reciprsa.data}, function(err, recipcsr) {
                                    if(err) {
                                        console.log(err);
                                    } else {
                                        console.log(recipcsr.data);
                                        openssl.x509.CASignCSR({
                                            key: reciprootcarsa.data,
                                            ca: reciprootcacert.data,
                                            csr: recipcsr.data,
                                            options: recipcsroptions
                                        }, function(err, recipcert) {
                                            if(err) {
                                                console.log(err);
                                            } else {
                                                console.log(recipcert);
                                                openssl.keypair.generateRSA({}, function(err, senderrootcarsa) {
                                                    if(err) {
                                                        console.log(err);
                                                    } else {
                                                        console.log(senderrootcarsa.data);
                                                        openssl.csr.create({options: sendercacsroptions, key: senderrootcarsa.data}, function(err, sendercacsr) {
                                                            if(err) {
                                                                console.log(err);
                                                            } else {
                                                                console.log(sendercacsr.data);
                                                                openssl.x509.selfSignCSR({options: sendercacsroptions, csr: sendercacsr.data, key: senderrootcarsa.data}, function(err, senderrootcacert) {
                                                                    if(err) {
                                                                        console.log(err);
                                                                    } else {
                                                                        console.log(senderrootcacert);
                                                                        openssl.keypair.generateRSA({}, function(err, senderrsa) {
                                                                            if(err) {
                                                                                console.log(err);
                                                                            } else {
                                                                                console.log(senderrsa.data);
                                                                                openssl.csr.create({options: sendercsroptions, key: senderrsa.data}, function(err, sendercsr) {
                                                                                    if(err) {
                                                                                        console.log(err);
                                                                                    } else {
                                                                                        console.log(sendercsr.data);
                                                                                        openssl.x509.CASignCSR({
                                                                                            key: senderrootcarsa.data,
                                                                                            ca: senderrootcacert.data,
                                                                                            csr: sendercsr.data,
                                                                                            options: sendercsroptions
                                                                                        }, function(err, sendercert) {
                                                                                            if(err) {
                                                                                                console.log(err);
                                                                                            } else {
                                                                                                console.log(sendercert);
                                                                                                openssl.smime.encrypt({cert: recipcert.data, data: 'this is my secret'}, function(err, encrypt) {
                                                                                                    if(err) {
                                                                                                        console.log(err);
                                                                                                    } else {
                                                                                                        console.log(encrypt.data);
                                                                                                        openssl.smime.sign({
                                                                                                            cert: sendercert.data,
                                                                                                            key: senderrsa.data,
                                                                                                            data: encrypt.data
                                                                                                        }, function(err, signed) {
                                                                                                            if(err) {
                                                                                                                console.log(err);
                                                                                                            } else {
                                                                                                                console.log(signed.data);
                                                                                                                openssl.smime.verify({data: signed.data, ca: senderrootcacert.data}, function(err, verify) {
                                                                                                                    if(err) {
                                                                                                                        console.log(err);
                                                                                                                    } else {
                                                                                                                        console.log(verify);
                                                                                                                        openssl.smime.decrypt({
                                                                                                                            cert: recipcert.data,
                                                                                                                            key: reciprsa.data,
                                                                                                                            data: verify.data
                                                                                                                        }, function(err, decrypt) {
                                                                                                                            if(err) {
                                                                                                                                console.log(err);
                                                                                                                            } else {
                                                                                                                                console.log(decrypt);
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
                                                            }
                                                        });
                                                    }
                                                });
                                            }
                                        })
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