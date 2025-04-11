const node_openssl = require('../index.js');
var openssl = new node_openssl({debug: false});

let rootcarsaoptions = {
    encryption: {
		password: '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\',
		cipher: 'aes-256-cbc'
	},
    format: "PKCS8"
}

let subcarsaoptions = {
    encryption: {
		password: 'subcapassword',
		cipher: 'aes-256-cbc'
	},
    format: "PKCS8"
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

var csroptions = {
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

openssl.keypair.generateRSA(rootcarsaoptions, function(err, rootcarsa) {
    if(err) {
        console.log(err);
    } else {
        //console.log(rootcarsa.data);
        openssl.csr.create({options: rootcacsroptions, key: rootcarsa.data, password: rootcarsaoptions.encryption.password}, function(err, csr) {
            if(err) {
                console.log(err);
            } else {
                //console.log(csr.data);
				openssl.x509.selfSignCSR({options: rootcacsroptions, csr: csr.data, key: rootcarsa.data, password: rootcarsaoptions.encryption.password}, function(err, rootcacert) {
					if(err) {
						console.log(err);
					} else {
						//console.log(rootcacert.data);
						openssl.keypair.generateRSA(subcarsaoptions, function(err, subcarsa) {
							if(err) {
								console.log(err);
							} else {
								//console.log(subcarsa.data);
								openssl.csr.create({options: subcacsroptions, key: subcarsa.data, password: subcarsaoptions.encryption.password}, function(err, subcacsr) {
									if(err) {
										console.log(err);
									} else {
										//console.log(subcacsr.data);
										openssl.x509.CASignCSR({
											key: rootcarsa.data,
											password: rootcarsaoptions.encryption.password,
											ca: rootcacert.data,
											csr: subcacsr.data,
											options: subcacsroptions
										}, function(err, subcacert) {
											if(err) {
												console.log(err);
											} else {
												//console.log(subcacert.data);
												openssl.keypair.generateRSA({}, function(err, rsacert) {
													if(err) {
														console.log(err);
													} else {
														//console.log(rsacert.data);
														openssl.csr.create({options: csroptions, key: rsacert.data}, function(err, csrcert) {
															if(err) {
																console.log(err);
															} else {
																//console.log(csrcert.data);
																openssl.x509.CASignCSR({
																	key: subcarsa.data,
																	password: subcarsaoptions.encryption.password,
																	ca: subcacert.data,
																	csr: csrcert.data,
																	options: csroptions
																}, function(err, leafcert) {
																	if(err) {
																		console.log(err);
																	} else {
																		//console.log(leafcert.data);
                                                                        openssl.x509.createPKCS12({
                                                                            cert: leafcert.data,
                                                                            key: rsacert.data,
                                                                            ca: rootcacert.data + '\r\n' + subcacert.data,
                                                                            pkcs12pass: 'test',
																			legacy: true
                                                                        }, function(err, pkcs12) {
                                                                            if(err) {
                                                                                console.log(err);
                                                                            } else {
                                                                                //fs.writeFile('./test_files/pkcs12.pfx', pkcs12.data, function(err) {
                                                
                                                                                //});
																				// console.log(pkcs12);
                                                                                openssl.x509.getKeyFromPKCS12({pkcs12: pkcs12.data, password: 'test', legacy: true}, function(err, key) {
                                                                                    if(err) {
                                                                                        console.log(err);
                                                                                    } else {
                                                                                        //console.log(key.data);
                                                                                        openssl.x509.getCertFromPKCS12({pkcs12: pkcs12.data, password: 'test', legacy: true}, function(err, cert) {
                                                                                            if(err) {
                                                                                                console.log(err);
                                                                                            } else {
                                                                                                //console.log(cert.data);
                                                                                                openssl.x509.getChainFromPKCS12({pkcs12: pkcs12.data, password: 'test', legacy: true}, function(err, chain) {
                                                                                                    if(err) {
                                                                                                        console.log(err);
                                                                                                    } else {
                                                                                                        console.log(chain.data[1]);
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
				});
            }
        });
    }
});

/*openssl.keypair.generateRSA(rootcarsaoptions, function(err, rootcarsa) {
    if(err) {
        console.log(err);
    } else {
        //console.log(rootcarsa.data);
        openssl.csr.create({options: rootcacsroptions, key: rootcarsa.data, password: rootcarsaoptions.encryption.password}, function(err, csr) {
            if(err) {
                console.log(err);
            } else {
                //console.log(csr.data);
				openssl.x509.selfSignCSR({options: rootcacsroptions, csr: csr.data, key: rootcarsa.data, password: rootcarsaoptions.encryption.password}, function(err, rootcacert) {
					if(err) {
						console.log(err);
					} else {
                        openssl.x509.createPKCS12({
                            cert: rootcacert.data,
                            keypass: rootcarsaoptions.encryption.password,
                            key: rootcarsa.data,
                            pkcs12pass: 'test'
                        }, function(err, pkcs12) {
                            if(err) {
                                console.log(err);
                            } else {
                                openssl.x509.getKeyFromPKCS12({pkcs12: pkcs12.data, password: 'test'}, function(err, key) {
                                    if(err) {
                                        console.log(err);
                                    } else {
                                        //console.log(key.data);
                                        openssl.x509.getCertFromPKCS12({pkcs12: pkcs12.data, password: 'test'}, function(err, cert) {
                                            if(err) {
                                                //console.log(err);
                                            } else {
                                                //console.log(cert.data);
                                                openssl.x509.getChainFromPKCS12({pkcs12: pkcs12.data, password: 'test'}, function(err, chain) {
                                                    if(err) {
                                                        //console.log(err);
                                                    } else {
                                                        console.log(chain.data);
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
});*/