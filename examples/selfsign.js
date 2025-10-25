const node_openssl = require('../index.js');
// var openssl = new node_openssl({binpath: '/opt/openssl32/bin/openssl', debug: false});
var openssl = new node_openssl();

let rsaoptionsa = {
    encryption: {
		password: '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\',
		cipher: 'aes-256-cbc'
	},
    format: "PKCS1"
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

openssl.keypair.generateRSA(rsaoptionsa, function(err, rsa) {
    if(err) {
        console.log(err);
    } else {
        console.log(rsa.data);
        openssl.csr.create({options: csroptions, key: rsa.data, password: rsaoptionsa.encryption.password}, function(err, csr) {
            if(err) {
                console.log(err);
            } else {
                console.log(csr.data);
				openssl.x509.selfSignCSR({options: csroptions, csr: csr.data, key: rsa.data, password: rsaoptionsa.encryption.password}, function(err, cert) {
					if(err) {
						console.log(err);
					} else {
						console.log(cert.data);
						openssl.keypair.getRSAPublicKey({key: rsa.data, password: rsaoptionsa.encryption.password}, function(err, privresult) {
							if(err) {
								console.log(err);
							} else {
								console.log(privresult);
								openssl.x509.getCertPublicKey({cert: cert.data}, function(err, certresult) {
									if(err) {
										console.log(err);
									} else {
										console.log(certresult);
										if(certresult.data == privresult.data) {
											openssl.keypair.generateECC({}, function(err, ecc) {
												if(err) {
													console.log(err);
												} else {
													console.log(ecc.data);
													openssl.csr.create({options: csroptions, key: ecc.data}, function(err, csr) {
														if(err) {
															console.log(err);
														} else {
															console.log(csr.data);
															openssl.x509.selfSignCSR({options: csroptions, csr: csr.data, key: ecc.data}, function(err, cert) {
																if(err) {
																	console.log(err);
																} else {
																	console.log(cert.data);
																	openssl.keypair.getECCPublicKey({key: ecc.data}, function(err, privresult) {
																		if(err) {
																			console.log(err);
																		} else {
																			console.log(privresult);
																			openssl.x509.getCertPublicKey({cert: cert.data}, function(err, certresult) {
																				if(err) {
																					console.log(err);
																				} else {
																					console.log(certresult);
																					openssl.x509.parse({cert: cert.data}, function(err, certparse) {
																						if(err) {
																							console.log(err);
																						} else {
																							console.log(certparse.data);
																							console.log(openssl.x509.getDistinguishedName(certparse.data.subject));
																							if(certresult.data == privresult.data) {
																								console.log('success');
																								openssl.x509.getOpenSSLCertInfo({cert: cert.data}, function(err, out) {
																									if(err) {
																										console.log(err);
																									} else {
																										console.log(out.data);
																										openssl.x509.convertPEMtoDER(cert.data, function(err, der) {
																											if(err) {
																												console.log(err);
																											} else {
																												console.log(der.data);
																											}
																										});
																									}
																								});
																							}
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
										} else {
											console.log('not a match');
										}
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