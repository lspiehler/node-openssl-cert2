const node_openssl = require('../index.js');
var openssl = new node_openssl();

test('Generate root ca, intermediate and sign leaf cert', done => {
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
            domainComponent: [
                'lcmchealth',
                'net'
            ],
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
                            expect(subcacert.files.config.split('\n')[0].trim()).toMatch(/^\[ (req|ca) \]$/)
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
                                        expect(leafcert.files.config.split('\n')[0].trim()).toMatch(/^\[ (req|ca) \]$/)
                                        expect(typeof(leafcert.serial)).toBe("string")
                                        openssl.x509.parse({cert: leafcert.data}, function(err, certparse) {
                                            expect(err).toEqual(false);
                                            expect(certparse.data.extensions.SANs.otherName[0]).toBe(csroptions.extensions.SANs.otherName[0]);
                                            let types = Object.keys(csroptions.subject);
                                            for(let i = 0; i < types.length; i++) {
                                                //console.log(types[i]);
                                                expect(certparse.data.subject.hasOwnProperty(types[i])).toEqual(true);
                                                let objecttype = typeof(csroptions.subject[types[i]]);
                                                if(objecttype == 'string') {
                                                    expect(certparse.data.subject[types[i]]).toBe(csroptions.subject[types[i]])
                                                } else {
                                                    if(csroptions.subject[types[i]].length == 1) {
                                                        expect(certparse.data.subject[types[i]]).toBe(csroptions.subject[types[i]][0])
                                                    } else {
                                                        for(let j = 0; j < csroptions.subject[types[i]].length; j++) {
                                                            expect(certparse.data.subject[types[i]][j]).toBe(csroptions.subject[types[i]][j])
                                                        }
                                                    }
                                                }
                                            }
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