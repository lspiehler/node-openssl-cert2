const node_openssl = require('../index.js');
var openssl = new node_openssl({debug: false});
var moment = require('moment');

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

var subcaocspcsroptions = {
	hash: 'sha256',
	days: 240,
	extensions: {
		customOIDs: [
			{
				OID: '1.3.6.1.5.5.7.48.1.5',
				value: 'ASN1:NULL'
				// value: 'DER:05:00'
			}
		],
		keyUsage: {
			critical: true,
			usages: [
				'digitalSignature'
			]
		},
		extendedKeyUsage: {
			critical: true,
			usages: [
				//'serverAuth',
				'OCSPSigning'
			]
		}
	},
	subject: {
		countryName: 'US',
		commonName: [
			'OCSP Responder'
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
        console.log(rootcarsa.data);
        openssl.csr.create({options: rootcacsroptions, key: rootcarsa.data, password: rootcarsaoptions.encryption.password}, function(err, csr) {
            if(err) {
                console.log(err);
            } else {
                console.log(csr.data);
				openssl.x509.selfSignCSR({options: rootcacsroptions, csr: csr.data, key: rootcarsa.data, password: rootcarsaoptions.encryption.password}, function(err, rootcacert) {
					if(err) {
						console.log(err);
					} else {
						console.log(rootcacert.data);
						openssl.keypair.generateRSA(subcarsaoptions, function(err, subcarsa) {
							if(err) {
								console.log(err);
							} else {
								console.log(subcarsa.data);
								openssl.csr.create({options: subcacsroptions, key: subcarsa.data, password: subcarsaoptions.encryption.password}, function(err, subcacsr) {
									if(err) {
										console.log(err);
									} else {
										console.log(subcacsr.data);
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
												console.log(subcacert.data);
												openssl.keypair.generateRSA({}, function(err, rsacert) {
													if(err) {
														console.log(err);
													} else {
														console.log(rsacert.data);
														openssl.csr.create({options: csroptions, key: rsacert.data}, function(err, csrcert) {
															if(err) {
																console.log(err);
															} else {
																console.log(csrcert.data);
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
																		console.log(leafcert.data);
																		openssl.keypair.generateRSA({}, function(err, subcaocsprsa) {
																			if(err) {
																				console.log(err);
																			} else {
																				openssl.csr.create({options: subcacsroptions, key: subcaocsprsa.data, password: subcarsaoptions.encryption.password}, function(err, subcaocspcsr) {
																					if(err) {
																						console.log(err);
																					} else {
																						openssl.x509.CASignCSR({
																							key: subcarsa.data,
																							password: subcarsaoptions.encryption.password,
																							ca: subcacert.data,
																							csr: subcaocspcsr.data,
																							options: subcaocspcsroptions
																						}, function(err, ocspcert) {
																							if(err) {
																								console.log(err);
																							} else {
																								console.log('OCSP Cert:');
																								console.log(ocspcert.data);
																								openssl.ocsp.request({
																									ca: subcacert.data,
																									cert: leafcert.data,
																									hash: 'sha256'
																								}, function(err, ocspreq) {
																									if(err) {
																										console.log(err);
																									} else {
																										console.log(ocspreq);
																										openssl.x509.parse({cert: leafcert.data}, function(err, parsedleafcert) {
																											if(err) {
																												console.log(err);
																											} else {
																												//console.log(parseleafcert.data.attributes['Serial Number'].split(':').join('').toUpperCase());
																												let revoked = [];
																												revoked[parsedleafcert.data.attributes['Serial Number'].split(':').join('').toUpperCase()] = 'keyCompromise'
																												//revoked['6C1B17D5E80FF201A0BCB6BF1502F809E3A3FECE'] = 'superseded'
																												let database = [
																													['R', moment.utc(new Date()).add(200, 'days').toDate(), moment.utc(new Date()).toDate(), 'keyCompromise', parsedleafcert.data.attributes['Serial Number'].split(':').join('').toUpperCase(), 'unknown', openssl.x509.getDistinguishedName(parsedleafcert.data.subject)]
																												]
																												let index = openssl.crl.generateIndex(database);
																												openssl.ocsp.response({
																													key: subcaocsprsa.data,
																													cert: ocspcert.data,
																													ca: subcacert.data,
																													days: 10,
																													database: index,
																													request: ocspreq.data,
																													nonce: false
																												}, function(err, ocspresp) {
																													if(err) {
																														console.log(err);
																													} else {
																														console.log(ocspresp);
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
            }
        });
    }
});