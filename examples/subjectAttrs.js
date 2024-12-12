const node_openssl = require('../index.js');
const { domainComponent } = require('../lib/x509/nameMappings.js');
var openssl = new node_openssl({binpath: '/opt/openssl32/bin/openssl', debug: false});

let rsaoptionsa = {
    encryption: {
		password: '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\',
		cipher: 'aes-256-cbc'
	},
    format: "PKCS1"
}

var csroptions = {
	hash: 'sha256',
	days: 240,
	extensions: {
		customOIDs: [
			{
				OID: '1.3.6.1.4.1.11129.2.4.3',
				value: 'critical,ASN1:NULL'
			}
		],
		tlsfeature: ['status_request'],
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
		domainComponent: 'lcmchealth',
		surname: 'Lyas',
		serialNumber: 'dgfsadgfasdasd',
		title: 'Mr',
		givenName: 'Spiehler',
		emailAddress: 'myemail@domain.com',
		UID: 'asdjkfhgaskdj',
		initials: 'LJS',
		generationQualifier: 'Jr',
		dnQualifier: 'dnstuff',
		pseudonym: 'pseudo',
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
				openssl.csr.parse({csr: csr.data}, function(err, result) {
					console.log(result.data.subject);
					csroptions.subject = result.data.subject;
					openssl.csr.create({options: csroptions, key: rsa.data, password: rsaoptionsa.encryption.password}, function(err, csr) {
						if(err) {
							console.log(err);
						} else {
							//console.log(csr.data);
							openssl.csr.parse({csr: csr.data}, function(err, result) {
								console.log(result.data.subject);
								openssl.x509.selfSignCSR({options: csroptions, csr: csr.data, key: rsa.data, password: rsaoptionsa.encryption.password}, function(err, cert) {
									if(err) {
										console.log(err);
									} else {
										openssl.x509.parse({cert: cert.data}, function(err, certparse) {
											if(err) {
												console.log(err);
											} else {
												console.log(certparse.data.subject);
											}
										});
									}
								});
							})
						}
					});
				})
            }
        });
    }
});