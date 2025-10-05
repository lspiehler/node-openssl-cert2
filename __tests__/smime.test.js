const node_openssl = require('../index.js');
var openssl = new node_openssl();
var moment = require('moment');

const secret = 'this is my secret';

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
    startdate: moment.utc(new Date()).add(-5, 'hours').toDate(),
    enddate: moment.utc(new Date()).add(10, 'hours').toDate(),
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

test('create required certs and test smime functions', done => {
    openssl.keypair.generateRSA({}, function(err, reciprootcarsa) {
        expect(err).toEqual(false);
        expect(reciprootcarsa.data.split('\n')[0].trim()).toBe("-----BEGIN PRIVATE KEY-----")
        openssl.csr.create({options: recipcacsroptions, key: reciprootcarsa.data}, function(err, recipcsr) {
            expect(err).toEqual(false);
            expect(recipcsr.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE REQUEST-----")
            openssl.x509.selfSignCSR({options: recipcacsroptions, csr: recipcsr.data, key: reciprootcarsa.data}, function(err, reciprootcacert) {
                expect(err).toEqual(false);
                expect(reciprootcacert.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE-----")
                openssl.keypair.generateRSA({}, function(err, reciprsa) {
                    expect(err).toEqual(false);
                    expect(reciprsa.data.split('\n')[0].trim()).toBe("-----BEGIN PRIVATE KEY-----")
                    openssl.csr.create({options: recipcsroptions, key: reciprsa.data}, function(err, recipcsr) {
                        expect(err).toEqual(false);
                        expect(recipcsr.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE REQUEST-----")
                        openssl.x509.CASignCSR({
                            key: reciprootcarsa.data,
                            ca: reciprootcacert.data,
                            csr: recipcsr.data,
                            options: recipcsroptions
                        }, function(err, recipcert) {
                            expect(err).toEqual(false);
                            expect(recipcert.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE-----")
                            openssl.keypair.generateRSA({}, function(err, senderrootcarsa) {
                                expect(err).toEqual(false);
                                expect(senderrootcarsa.data.split('\n')[0].trim()).toBe("-----BEGIN PRIVATE KEY-----")
                                openssl.csr.create({options: sendercacsroptions, key: senderrootcarsa.data}, function(err, sendercacsr) {
                                    expect(err).toEqual(false);
                                    expect(sendercacsr.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE REQUEST-----")
                                    openssl.x509.selfSignCSR({options: sendercacsroptions, csr: sendercacsr.data, key: senderrootcarsa.data}, function(err, senderrootcacert) {
                                        expect(err).toEqual(false);
                                        expect(senderrootcacert.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE-----")
                                        openssl.keypair.generateRSA({}, function(err, senderrsa) {
                                            expect(err).toEqual(false);
                                            expect(senderrsa.data.split('\n')[0].trim()).toBe("-----BEGIN PRIVATE KEY-----")
                                            openssl.csr.create({options: sendercsroptions, key: senderrsa.data}, function(err, sendercsr) {
                                                expect(err).toEqual(false);
                                                expect(sendercsr.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE REQUEST-----")
                                                openssl.x509.CASignCSR({
                                                    key: senderrootcarsa.data,
                                                    ca: senderrootcacert.data,
                                                    csr: sendercsr.data,
                                                    options: sendercsroptions
                                                }, function(err, sendercert) {
                                                    expect(err).toEqual(false);
                                                    expect(sendercert.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE-----")
                                                    openssl.smime.encrypt({cert: recipcert.data, data: secret}, function(err, encrypt) {
                                                        expect(err).toEqual(false);
                                                        expect(encrypt.data.split('\n')[0].trim()).toBe("-----BEGIN CMS-----")
                                                        openssl.smime.sign({
                                                            cert: sendercert.data,
                                                            key: senderrsa.data,
                                                            data: encrypt.data
                                                        }, function(err, signed) {
                                                            expect(err).toEqual(false);
                                                            expect(signed.data.split('\n')[0].trim()).toBe("-----BEGIN CMS-----")
                                                            openssl.smime.verify({data: signed.data, ca: senderrootcacert.data}, function(err, verify) {
                                                                expect(err).toEqual(false);
                                                                expect(verify.data.split('\n')[0].trim()).toBe("-----BEGIN CMS-----")
                                                                expect(sendercert.data).toBe(verify.signercert)
                                                                openssl.smime.decrypt({
                                                                    cert: recipcert.data,
                                                                    key: reciprsa.data,
                                                                    data: verify.data
                                                                }, function(err, decrypt) {
                                                                    expect(err).toEqual(false);
                                                                    expect(decrypt.data.toString()).toBe(secret)
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