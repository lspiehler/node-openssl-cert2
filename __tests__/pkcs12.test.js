const node_openssl = require('../index.js');
var openssl = new node_openssl();

test('Generate cert, convert to PKCS12 and back', done => {
    var csroptions = {
        hash: 'sha256',
        extensions: {
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
                    'clientAuth'
                ]	
            },
            SANs: {
                DNS: ['certificatetools.com']
            }
        },
        subject: {
            countryName: 'US',
            commonName: ['certificatetools.com']
        }
    
    }
    
    openssl.keypair.generateRSA({}, function(err, rsa) {
        expect(err).toEqual(false);
        expect(rsa.data.split('\n')[0].trim()).toBe("-----BEGIN PRIVATE KEY-----")
        openssl.csr.create({options: csroptions, key: rsa.data}, function(err, csr) {
            expect(err).toEqual(false);
            expect(csr.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE REQUEST-----")
            openssl.x509.selfSignCSR({options: csroptions, csr: csr.data, key: rsa.data}, function(err, cert) {
                expect(err).toEqual(false);
                openssl.x509.createPKCS12({
                    cert: cert.data,
                    key: rsa.data,
                    pkcs12pass: 'test'
                }, function(err, pkcs12) {
                    expect(err).toEqual(false);
                    openssl.x509.getKeyFromPKCS12({pkcs12: pkcs12.data, password: 'test'}, function(err, key) {
                        expect(err).toEqual(false);
                        expect(key.data.split('\n')[0].trim()).toBe("-----BEGIN PRIVATE KEY-----")
                        openssl.x509.getCertFromPKCS12({pkcs12: pkcs12.data, password: 'test'}, function(err, cert) {
                            expect(err).toEqual(false);
                            expect(cert.data.split('\n')[0].trim()).toBe("-----BEGIN CERTIFICATE-----")
                            openssl.x509.getChainFromPKCS12({pkcs12: pkcs12.data, password: 'test'}, function(err, chain) {
                                expect(err).toEqual(false);
                                console.log(chain.data);
                                expect(chain.data.split('\n')[0].trim()).toBe("")
                                done();
                            });
                        });
                    });
                });
            });
        });
    });
});