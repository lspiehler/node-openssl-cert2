const node_openssl = require('../index.js');
var openssl = new node_openssl({binpath: "C:/Program Files/OpenSSL-Win64/bin/openssl.exe"});

test('generate RSA keypair', async () => {
    let rsaoptionsa = {
        encryption: {
            password: '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\',
            cipher: 'aes-256-cbc'
        },
        format: "PKCS1"
    }
    
    openssl.keypair.generateRSA(rsaoptionsa, function(err, rsa) {
        expect(err).toEqual(false);
        expect(rsa.stdout.split('\r\n')[0]).toBe("-----BEGIN RSA PRIVATE KEY-----")
        openssl.keypair.convertToPKCS8({key: rsa.stdout, password: rsaoptionsa.encryption.password}, function(err, pkcs8) {
            expect(err).toEqual(false);
            expect(pkcs8.stdout.split('\r\n')[0]).toBe("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        });
    });

    let rsaoptionsb = {
        encryption: {
            password: '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\',
            cipher: 'aes-256-cbc'
        },
        format: "PKCS1"
    }
    
    openssl.keypair.generateRSA({}, function(err, rsa) {
        expect(err).toEqual(false);
        expect(rsa.stdout.split('\r\n')[0]).toBe("-----BEGIN PRIVATE KEY-----")
        openssl.keypair.convertRSAToPKCS1({key: rsa.stdout, encryption: rsaoptionsb.encryption}, function(err, pkcs1) {
            expect(err).toEqual(false);
            expect(pkcs1.stdout.split('\r\n')[0]).toBe("-----BEGIN RSA PRIVATE KEY-----")
            openssl.keypair.convertToPKCS8({key: pkcs1.stdout, password: rsaoptionsb.encryption.password}, function(err, pkcs8) {
                expect(err).toEqual(false);
                expect(pkcs8.stdout.split('\r\n')[0]).toBe("-----BEGIN ENCRYPTED PRIVATE KEY-----")
                openssl.keypair.convertRSAToPKCS1({key: pkcs8.stdout, encryption: rsaoptionsb.encryption, decrypt: true}, function(err, pkcs1again) {
                    expect(err).toEqual(false);
                    expect(pkcs1again.stdout.split('\r\n')[0]).toBe("-----BEGIN RSA PRIVATE KEY-----")
                    openssl.keypair.convertToPKCS8({key: pkcs1again.stdout}, function(err, pkcs8again) {
                        expect(err).toEqual(false);
                        expect(pkcs8again.stdout.split('\r\n')[0]).toBe("-----BEGIN PRIVATE KEY-----")
                    });
                });
            });
        });
    });
});