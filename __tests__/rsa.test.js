const node_openssl = require('../index.js');
var openssl = new node_openssl();

test('Generate encrypted PKCS1 RSA keypair', async () => {
    let rsaoptions = {
        encryption: {
            password: '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\',
            cipher: 'aes-256-cbc'
        },
        format: "PKCS1"
    }
    
    openssl.keypair.generateRSA(rsaoptions, function(err, rsa) {
        expect(err).toEqual(false);
        expect(rsa.data.split('\n')[0].trim()).toBe("-----BEGIN RSA PRIVATE KEY-----")
    });
});

test('Generate unencrypted PKCS1 RSA keypair', async () => {
    let rsaoptions = {
        format: "PKCS1"
    }
    
    openssl.keypair.generateRSA(rsaoptions, function(err, rsa) {
        expect(err).toEqual(false);
        expect(rsa.data.split('\n')[0].trim()).toBe("-----BEGIN RSA PRIVATE KEY-----")
    });
});

test('Generate encrypted PKCS8 RSA keypair', async () => {
    let rsaoptions = {
        encryption: {
            password: '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\',
            cipher: 'aes-256-cbc'
        },
        format: "PKCS8"
    }
    
    openssl.keypair.generateRSA(rsaoptions, function(err, rsa) {
        expect(err).toEqual(false);
        expect(rsa.data.split('\n')[0].trim()).toBe("-----BEGIN ENCRYPTED PRIVATE KEY-----")
    });
});

test('Generate unencrypted PKCS8 RSA keypair', async () => {
    let rsaoptions = {
        format: "PKCS8"
    }
    
    openssl.keypair.generateRSA(rsaoptions, function(err, rsa) {
        expect(err).toEqual(false);
        expect(rsa.data.split('\n')[0].trim()).toBe("-----BEGIN PRIVATE KEY-----")
    });
});

test('Generate RSA keypair. Test convert, encrypt and decrypt', async () => {
    let rsaoptions = {
        encryption: {
            password: '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\',
            cipher: 'aes-256-cbc'
        },
        format: "PKCS1"
    }
    
    openssl.keypair.generateRSA({}, function(err, rsa) {
        expect(err).toEqual(false);
        expect(rsa.data.split('\n')[0].trim()).toBe("-----BEGIN PRIVATE KEY-----")
        openssl.keypair.convertRSAToPKCS1({key: rsa.data, encryption: rsaoptions.encryption}, function(err, pkcs1) {
            expect(err).toEqual(false);
            expect(pkcs1.data.split('\n')[0].trim()).toBe("-----BEGIN RSA PRIVATE KEY-----")
            openssl.keypair.convertToPKCS8({key: pkcs1.data, password: rsaoptions.encryption.password}, function(err, pkcs8) {
                expect(err).toEqual(false);
                expect(pkcs8.data.split('\n')[0].trim()).toBe("-----BEGIN ENCRYPTED PRIVATE KEY-----")
                openssl.keypair.convertRSAToPKCS1({key: pkcs8.data, encryption: rsaoptions.encryption, decrypt: true}, function(err, pkcs1again) {
                    expect(err).toEqual(false);
                    expect(pkcs1again.data.split('\n')[0].trim()).toBe("-----BEGIN RSA PRIVATE KEY-----")
                    openssl.keypair.convertToPKCS8({key: pkcs1again.data}, function(err, pkcs8again) {
                        expect(err).toEqual(false);
                        expect(pkcs8again.data.split('\n')[0].trim()).toBe("-----BEGIN PRIVATE KEY-----")
                    });
                });
            });
        });
    });
});