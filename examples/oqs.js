const node_openssl = require('../index.js');
var openssl = new node_openssl({binpath: '/opt/openssl32/bin/openssl', debug: false});

const algorithm = 'mldsa44'
//const algorithm = 'dilithium2'
//const algorithm = 'falcon512'

let rootcakeyoptions = {
    algorithm: algorithm,
    encryption: {
        cipher: 'aes256',
        password: 'hello!!!'
    }
}

let subcakeyoptions = {
    algorithm: algorithm,
    encryption: {
        cipher: 'aes256',
        password: 'hello!!!'
    }
}

let certkeyoptions = {
    algorithm: algorithm,
    encryption: {
        cipher: 'aes256',
        password: 'hello!!!'
    }
}

var rootcacsroptions = {
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
			'Test Root CA'
		]
	}
}

var subcacsroptions = {
	hash: 'sha256',
	days: 240,
	extensions: {
		basicConstraints: {
			critical: true,
			CA: true,
			pathlen: 1
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
			'Test Intermediate CA'
		]
	}
}

var certcsroptions = {
	hash: 'sha512',
	days: 240,
	requestAttributes: {
		challengePassword: "this is my challenge passphrase"
	},
	string_mask: "nombstr",
	extensions: {
		customOIDs: [
			{
				OID: '1.3.6.1.4.1.311.20.2',
				value: 'ASN1:PRINTABLESTRING:Test Template'
			},
			{
				OID: '1.3.6.1.4.1.11129.2.4.3',
				value: 'critical,ASN1:NULL'
			}
		],
		tlsfeature: ['status_request'],
		basicConstraints: {
			critical: true,
			CA: true,
			pathlen: 1
		},
		keyUsage: {
			critical: true,
			usages: [
				'digitalSignature',
				'keyEncipherment'
			]
		},
		extendedKeyUsage: {
			critical: true,
			usages: [
				'serverAuth',
				'clientAuth',
				'ipsecIKE',
				'ipsecUser',
				'ipsecTunnel',
				'ipsecEndSystem',
				'1.3.6.1.4.1.311.10.3.1',
				'1.3.6.1.4.1.311.10.3.3',
				'1.3.6.1.4.1.311.10.3.4'
			]	
		},
		SANs: {
			DNS: [
				'certificatetools.com',
				'www.certificatetools.com'
			],
			otherName: [
				'msUPN;UTF8:lspiehler',
				'1.2.3.4;UTCTIME:240101010101Z',
			]
		}
	},
	subject: {
		countryName: 'US',
		stateOrProvinceName: 'Louisiana',
		localityName: 'Slidell',
		postalCode: '70458',
		streetAddress: '1001 Gause Blvd.',
		organizationName: 'SMH',
		organizationalUnitName: [
				'IT'
		],
		commonName: [
				'certificatetools.com',
				'www.certificatetools.com'
		],
		emailAddress: 'email@domain.com'
	}

}

openssl.keypair.generateOQSKey(rootcakeyoptions, function(err, rootcakey) {
    if(err) {
        console.log(err);
    } else {
        console.log(rootcakey.data);
        openssl.csr.create({options: rootcacsroptions, key: rootcakey.data, password: rootcakeyoptions.encryption.password}, function(err, rootcacsr) {
            if(err) {
                console.log(err);
            } else {
                console.log(rootcacsr.data);
                openssl.x509.selfSignCSR({options: rootcacsroptions, csr: rootcacsr.data, key: rootcakey.data, password: rootcakeyoptions.encryption.password}, function(err, rootcacert) {
					if(err) {
						console.log(err);
					} else {
                        console.log(rootcacert.data);
                        openssl.keypair.generateOQSKey(subcakeyoptions, function(err, subcakey) {
                            if(err) {
                                console.log(err);
                            } else {
                                console.log(subcakey.data);
                                openssl.csr.create({options: subcacsroptions, key: subcakey.data, password: subcakeyoptions.encryption.password}, function(err, subcacsr) {
                                    if(err) {
                                        console.log(err);
                                    } else {
                                        console.log(subcacsr.data);
                                        openssl.x509.CASignCSR({
											key: rootcakey.data,
											password: rootcakeyoptions.encryption.password,
											ca: rootcacert.data,
											csr: subcacsr.data,
											options: subcacsroptions
										}, function(err, subcacert) {
											if(err) {
												console.log(err);
											} else {
                                                console.log(subcacert.data);
                                                openssl.keypair.generateOQSKey(certkeyoptions, function(err, certkey) {
													if(err) {
														console.log(err);
													} else {
														console.log(certkey.data);
														openssl.csr.create({options: certcsroptions, key: certkey.data, password: certkeyoptions.encryption.password}, function(err, certcsr) {
															if(err) {
																console.log(err);
															} else {
																console.log(certcsr.data);
																openssl.x509.CASignCSR({
																	key: subcakey.data,
																	password: subcakeyoptions.encryption.password,
																	ca: subcacert.data,
																	csr: certcsr.data,
																	options: certcsroptions
																}, function(err, leafcert) {
																	if(err) {
																		console.log(err);
																	} else {
																		console.log(leafcert.data);
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