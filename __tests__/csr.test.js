const node_openssl = require('../index.js');
var openssl = new node_openssl();

test('Generate a CSR', done => {
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
            emailAddress: 'email@domain.com'
        }
    
    }
    
    openssl.keypair.generateRSA(rsaoptionsa, function(err, rsa) {
        expect(err).toEqual(false);
        expect(rsa.data.split('\n')[0].trim()).toBe("-----BEGIN RSA PRIVATE KEY-----")
        openssl.csr.create({options: csroptions, key: rsa.data, password: rsaoptionsa.encryption.password}, function(err, csr) {
            expect(err).toEqual(false);
            expect(csr.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE REQUEST-----")
            openssl.csr.parse({csr: csr.data}, function(err, parsedcsr) {
                expect(err).toEqual(false);
                expect(parsedcsr.data.extensions.SANs.otherName[1]).toBe(csroptions.extensions.SANs.otherName[1])
                openssl.keypair.generateRSA({}, function(err, rsa) {
                    expect(err).toEqual(false);
                    expect(rsa.data.split('\n')[0].trim()).toBe("-----BEGIN PRIVATE KEY-----")
                    openssl.csr.create({options: parsedcsr.data, key: rsa.data}, function(err, csr) {
                        expect(err).toEqual(false);
                        expect(csr.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE REQUEST-----")
                        openssl.csr.parse({csr: csr.data}, function(err, parsedcsr) {  
                            expect(err).toEqual(false);
                            expect(parsedcsr.data.extensions.SANs.otherName[0]).toBe(csroptions.extensions.SANs.otherName[0])
                            done();
                        });
                    });
                });
            });
        });
    });
});