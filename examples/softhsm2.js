const node_openssl = require('../index.js');
var openssl = new node_openssl({binpath: 'openssl', debug: false});
const fs = require('fs');

const label = 'test';
const pin = '123456';
const lib = '/usr/lib/softhsm/libsofthsm2.so'

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
				'www.certificatetools.com',
				'⚙️'
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

const deleteTestSlotIfExists = function(slots, callback) {
	let foundtestslot = -1;
	for(let i = 0; i < slots.data.length; i++) {
		if(slots.data[i]['token label']==label) {
			foundtestslot = i;
			break;
		}
	}
	if(foundtestslot >= 0) {
		openssl.softhsm2.deleteSlot({serial: slots.data[foundtestslot]['serial num']}, function(err, result) {
			callback(err, result);
		});
	} else {
		callback(false, false);
	}
}

fs.stat(lib, function(err, stat) {
	if(err) {
		console.log('The following packages should be installed before this test will run: softhsm2, opensc, and libengine-pkcs11-openssl')
	} else {
		//console.log(stat);
		openssl.pkcs11.listSlots({modulePath: lib}, function(err, slots, cmd) {
			if(err) {
				console.log(err);
			} else {
				deleteTestSlotIfExists(slots, function(err, result) {
					if(err) {
						console.log(err);
					} else {
						if(result) {
							console.log(result);
						}
						openssl.softhsm2.createSlot({modulePath: lib, label: label, pin: pin, sopin: pin}, function(err, softhsm) {
							if(err) {
								console.log(err);
							} else {
								console.log(softhsm);
								console.log('here');
								openssl.pkcs11.listObjects({
									modulePath: lib,
									slotid: softhsm.data.hexid
								}, function(err, objects) {
									if(err) {
										console.log(err);
									} else {
										console.log(objects);
										openssl.pkcs11.generateKeyPair({
											modulePath: lib,
											label: label,
											slotid: softhsm.data.hexid,
											objectid: '00',
											keytype: 'rsa:2048',
											pin: pin,
											loginType: "User",
											serial: softhsm.data['serial num'],
											signpin: pin
										}, function(err, kpresult) {
											if(err) {
												console.log(err);
											} else {
												console.log(kpresult);
												openssl.x509.selfSignCSR({
													options: rootcacsroptions,
													//csr: csr.data,
													pkcs11: {
														modulePath: lib,
														pin: pin,
														serial: softhsm.data['serial num'],
														objectid: kpresult.data[0]['ID']
													}
												}, function(err, rootcacert) {
													if(err) {
														console.log(err);
													} else {
														console.log('TESTING');
														console.log(rootcacert);
														openssl.x509.parse({cert: rootcacert.data}, function(err, caparse) {
															if(err) {
																console.log(err);
															} else {
																console.log(caparse.data.attributes['Subject String']);
																openssl.pkcs11.importCertificate({
																	modulePath: lib,
																	label: label,
																	slotid: softhsm.data.hexid,
																	objectid: kpresult.data[0]['ID'],
																	keytype: 'rsa:2048',
																	pin: pin,
																	loginType: "User",
																	serial: softhsm.data['serial num'],
																	cert: rootcacert.data
																}, function(err, resp) {
																	if(err) {
																		console.log(err);
																	} else {
																		console.log(resp);
																		openssl.pkcs11.listObjects({
																			modulePath: lib,
																			slotid: softhsm.data.hexid
																		}, function(err, objects) {
																			if(err) {
																				console.log(err);
																			} else {
																				console.log(objects);
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
																									ca: rootcacert.data,
																									csr: csrcert.data,
																									options: csroptions,
																									pkcs11: {
																										serial: softhsm.data['serial num'],
																										objectid: kpresult.data[0]['ID'],
																										pin: pin,
																										modulePath: lib
																									}
																								}, function(err, leafcert) {
																									if(err) {
																										console.log(err);
																									} else {
																										console.log(leafcert);
																										console.log(leafcert.data);
																										openssl.x509.parse({cert: leafcert.data}, function(err, certparse) {
																											if(err) {
																												console.log(err);
																											} else {
																												console.log(csroptions.extensions.SANs.DNS[2]);
																												console.log(certparse.data.extensions.SANs.DNS[2]);
																												let revoked = [];
																												revoked[leafcert.serial] = 'keyCompromise'
																												openssl.crl.generate({
																													ca: rootcacert.data,
																													crldays: 90,
																													revoked: revoked,
																													pkcs11: {
																														serial: softhsm.data['serial num'],
																														objectid: kpresult.data[0]['ID'],
																														pin: pin,
																														modulePath: lib
																													}
																												}, function(err, crl) {
																													if(err) {
																														console.log(err);
																													} else {
																														console.log(crl.data);
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