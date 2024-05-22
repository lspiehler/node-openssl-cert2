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

var subcaocspcsroptions = {
	hash: 'sha256',
	days: 240,
	extensions: {
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

test('create required certs and test ocsp functions', done => {
    openssl.keypair.generateRSA(rootcarsaoptions, function(err, rootcarsa) {
        expect(err).toEqual(false);
        expect(rootcarsa.data.split('\n')[0].trim()).toBe("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        openssl.csr.create({options: rootcacsroptions, key: rootcarsa.data, password: rootcarsaoptions.encryption.password}, function(err, rootcacsr) {
            expect(err).toEqual(false);
            expect(rootcacsr.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE REQUEST-----")
            openssl.x509.selfSignCSR({options: rootcacsroptions, csr: rootcacsr.data, key: rootcarsa.data, password: rootcarsaoptions.encryption.password}, function(err, rootcacert) {
                expect(err).toEqual(false);
                expect(rootcacert.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE-----")
                openssl.keypair.generateRSA(subcarsaoptions, function(err, subcarsa) {
                    expect(err).toEqual(false);
                    expect(subcarsa.data.split('\n')[0].trim()).toBe("-----BEGIN ENCRYPTED PRIVATE KEY-----")
                    openssl.csr.create({options: subcacsroptions, key: subcarsa.data, password: subcarsaoptions.encryption.password}, function(err, subcacsr) {
                        expect(err).toEqual(false);
                        expect(subcacsr.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE REQUEST-----")
                        openssl.x509.CASignCSR({
                            key: rootcarsa.data,
                            password: rootcarsaoptions.encryption.password,
                            ca: rootcacert.data,
                            csr: subcacsr.data,
                            options: subcacsroptions
                        }, function(err, subcacert) {
                            expect(err).toEqual(false);
                            expect(subcacert.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE-----")
                            expect(subcacert.files.config.split('\n')[0].trim()).toBe("[ ca ]")
                            expect(typeof(subcacert.serial)).toBe("string")
                            openssl.keypair.generateRSA({}, function(err, rsacert) {
                                expect(err).toEqual(false);
                                expect(rsacert.data.split('\n')[0].trim()).toBe("-----BEGIN PRIVATE KEY-----")
                                openssl.csr.create({options: csroptions, key: rsacert.data}, function(err, csrcert) {
                                    expect(err).toEqual(false);
                                    expect(csrcert.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE REQUEST-----")
                                    openssl.x509.CASignCSR({
                                        key: subcarsa.data,
                                        password: subcarsaoptions.encryption.password,
                                        ca: subcacert.data,
                                        csr: csrcert.data,
                                        options: csroptions
                                    }, function(err, leafcert) {
                                        expect(err).toEqual(false);
                                        expect(leafcert.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE-----")
                                        expect(leafcert.files.config.split('\n')[0].trim()).toBe("[ ca ]")
                                        expect(typeof(leafcert.serial)).toBe("string")
                                        openssl.keypair.generateRSA({}, function(err, subcaocsprsa) {
                                            expect(err).toEqual(false);
                                            expect(subcaocsprsa.data.split('\n')[0].trim()).toBe("-----BEGIN PRIVATE KEY-----")
                                            openssl.csr.create({options: subcacsroptions, key: subcaocsprsa.data, password: subcarsaoptions.encryption.password}, function(err, subcaocspcsr) {
                                                expect(err).toEqual(false);
                                                expect(subcaocspcsr.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE REQUEST-----")
                                                openssl.x509.CASignCSR({
                                                    key: subcarsa.data,
                                                    password: subcarsaoptions.encryption.password,
                                                    ca: subcacert.data,
                                                    csr: subcaocspcsr.data,
                                                    options: subcaocspcsroptions
                                                }, function(err, ocspcert) {
                                                    expect(err).toEqual(false);
                                                    expect(ocspcert.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE-----")
                                                    expect(ocspcert.files.config.split('\n')[0].trim()).toBe("[ ca ]")
                                                    expect(typeof(ocspcert.serial)).toBe("string")
                                                    openssl.ocsp.request({
                                                        ca: subcacert.data,
                                                        cert: leafcert.data,
                                                        hash: 'sha256'
                                                    }, function(err, ocspreq) {
                                                        expect(err).toEqual(false);
                                                        expect(Buffer.isBuffer(ocspreq.data)).toBe(true)
                                                        expect(ocspreq.text.split('\n')[0].trim()).toBe("OCSP Request Data:")
                                                        openssl.x509.parse({cert: leafcert.data}, function(err, parseleafcert) {
                                                            expect(err).toEqual(false);
                                                            expect(ocspreq.text.indexOf(parseleafcert.data.attributes['Serial Number'].split(':').join('').toUpperCase()) >= 0).toEqual(true)
                                                            let revoked = [];
                                                            revoked[parseleafcert.data.attributes['Serial Number'].split(':').join('').toUpperCase()] = 'keyCompromise'
                                                            openssl.ocsp.response({
                                                                key: subcaocsprsa.data,
                                                                cert: ocspcert.data,
                                                                ca: subcacert.data,
                                                                days: 10,
                                                                revoked: revoked,
                                                                request: ocspreq.data,
                                                                nonce: false
                                                            }, function(err, ocsprevokedresp) {
                                                                expect(err).toEqual(false);
                                                                expect(ocsprevokedresp.text.indexOf('Cert Status: revoked') >= 0).toEqual(true);
                                                                revoked[parseleafcert.data.attributes['Serial Number'].split(':').join('').toUpperCase()] = false
                                                                openssl.ocsp.response({
                                                                    key: subcaocsprsa.data,
                                                                    cert: ocspcert.data,
                                                                    ca: subcacert.data,
                                                                    days: 10,
                                                                    revoked: revoked,
                                                                    request: ocspreq.data,
                                                                    nonce: false
                                                                }, function(err, ocspvalidresp) {
                                                                    expect(err).toEqual(false);
                                                                    expect(ocspvalidresp.text.indexOf('Cert Status: good') >= 0).toEqual(true);
                                                                    done();
                                                                });
                                                            });
                                                        });
                                                    });
                                                });
                                            });
                                        });
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});