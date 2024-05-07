const node_openssl = require('../index.js');
var openssl = new node_openssl();

test('Generate a self signed certificate', done => {
    let rsaoptionsa = {
        encryption: {
            password: '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\',
            cipher: 'aes-256-cbc'
        },
        format: "PKCS1"
    }
    
    var csroptions = {
        hash: 'sha512',
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
            emailAddress: 'lyas.spiehler@slidellmemorial.org'
        }
    
    }
    
    openssl.keypair.generateRSA(rsaoptionsa, function(err, rsa) {
        expect(err).toEqual(false);
        expect(rsa.data.split('\n')[0].trim()).toBe("-----BEGIN RSA PRIVATE KEY-----")
        openssl.csr.create({options: csroptions, key: rsa.data, password: rsaoptionsa.encryption.password}, function(err, csr) {
            expect(err).toEqual(false);
            expect(csr.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE REQUEST-----")
            openssl.x509.selfSignCSR({options: csroptions, csr: csr.data, key: rsa.data, password: rsaoptionsa.encryption.password}, function(err, cert) {
                expect(err).toEqual(false);
                expect(cert.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE-----")
                openssl.keypair.getRSAPublicKey({key: rsa.data, password: rsaoptionsa.encryption.password}, function(err, privresult) {
                    expect(err).toEqual(false);
                    openssl.x509.getCertPublicKey({cert: cert.data}, function(err, certresult) {
                        expect(err).toEqual(false);
                        expect(privresult.data).toBe(certresult.data);
                        openssl.keypair.generateECC({}, function(err, ecc) {
                            expect(err).toEqual(false);
                            expect(ecc.data.split('\n')[0].trim()).toBe("-----BEGIN PRIVATE KEY-----")
                            openssl.csr.create({options: csroptions, key: ecc.data}, function(err, csr) {
                                expect(err).toEqual(false);
                                expect(csr.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE REQUEST-----")
                                openssl.x509.selfSignCSR({options: csroptions, csr: csr.data, key: ecc.data}, function(err, cert) {
                                    expect(err).toEqual(false);
                                    expect(cert.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE-----")
                                    openssl.keypair.getECCPublicKey({key: ecc.data }, function(err, privresult) {
                                        expect(err).toEqual(false);
                                        openssl.x509.getCertPublicKey({cert: cert.data}, function(err, certresult) {
                                            expect(err).toEqual(false);
                                            expect(privresult.data).toBe(certresult.data);
                                            openssl.x509.parse({cert: cert.data}, function(err, certparse) {
                                                expect(err).toEqual(false);
                                                expect(certparse.data.extensions.SANs.otherName[0]).toBe(csroptions.extensions.SANs.otherName[0]);
                                                openssl.x509.getOpenSSLCertInfo({cert: cert.data}, function(err, out) {
                                                    expect(err).toEqual(false);
                                                    expect(out.data.split('\n')[0].trim()).toBe("Certificate:")
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