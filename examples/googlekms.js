const node_openssl = require('../index.js');
var openssl = new node_openssl({binpath: 'openssl', debug: false});

// const lib = '/usr/lib/x86_64-linux-gnu/libykcs11.so';
const lib = '/usr/local/lib/kms/libkmsp11.so';
// const lib = '/usr/lib/x86_64-linux-gnu/pkcs11-spy.so';

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
	hash: 'sha256',
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

openssl.pkcs11.listSlots({modulePath: lib}, function(err, slots, cmd) {
    if(err) {
        console.log(err);
    } else {
        console.log(slots);
        if(slots.data.length < 1) {
            console.log('no slots found');
        } else {
            openssl.pkcs11.listObjects({
                modulePath: lib,
                slotid: slots.data[0].hexid
            }, function(err, objects) {
                if(err) {
                    console.log(err);
                } else {
                    console.log(objects);
                    // console.log(process.env);
                    openssl.pkcs11.readObject({
                        modulePath: lib,
                        slotid: slots.data[0].hexid,
                        type: 'pubkey',
                        objectid: objects.data[0]['ID']
                    }, function(err, pubkey) {
                        if(err) {
                            console.log(err);
                        } else {
                            console.log(pubkey.data);
                            openssl.x509.selfSignCSR({
                                options: rootcacsroptions,
                                //csr: csr.data,
                                pkcs11: {
                                    modulePath: '/usr/lib/x86_64-linux-gnu/pkcs11-spy.so',
                                    // pin: '123456',
                                    uri: openssl.common.encodePKCS11URI({
                                        serial: slots.data[0]['serial num'],
                                        object: objects.data[0]['label'],
                                        type: 'private'
                                    })
                                }
                            }, function(err, rootcacert) {
                                if(err) {
                                    console.log(err);
                                } else {
                                    console.log('TESTING');
                                    console.log(rootcacert);
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
                                                        // hash: 'sha256',
                                                        options: csroptions,
                                                        pkcs11: {
                                                            // pin: '765432',
                                                            modulePath: lib,
                                                            uri: openssl.common.encodePKCS11URI({
                                                                serial: slots.data[0]['serial num'],
                                                                object: objects.data[0]['label'],
                                                                type: 'private'
                                                            })
                                                        }
                                                    }, function(err, leafcert) {
                                                        if(err) {
                                                            console.log(err);
                                                            console.log(leafcert);
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
    }
});