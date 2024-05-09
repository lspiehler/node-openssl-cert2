const node_openssl = require('../index.js');
var openssl = new node_openssl({debug: false});

let rootcarsaoptions = {
    encryption: {
		password: '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\',
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

openssl.keypair.generateRSA(rootcarsaoptions, function(err, rsa) {
    if(err) {
        console.log(err);
    } else {
        console.log(rsa.data);
        openssl.csr.create({options: rootcacsroptions, key: rsa.data, password: rootcarsaoptions.encryption.password}, function(err, csr) {
            if(err) {
                console.log(err);
            } else {
                console.log(csr.data);
				openssl.x509.selfSignCSR({options: rootcacsroptions, csr: csr.data, key: rsa.data, password: rootcarsaoptions.encryption.password}, function(err, cert) {
					if(err) {
						console.log(err);
					} else {
						console.log(cert.data);
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
											key: rsa.data,
											password: rootcarsaoptions.encryption.password,
											ca: cert.data,
											csr: csrcert.data,
											options: csroptions
										}, function(err, sign) {
											if(err) {
												console.log(err);
											} else {
												console.log(sign);
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