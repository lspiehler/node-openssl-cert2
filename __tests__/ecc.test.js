const node_openssl = require('../index.js');
var openssl = new node_openssl();

test('List supported curves', done => {
    openssl.keypair.listECCCurves(function(err, curves) {
        expect(err).toEqual(false);
        expect(typeof curves).toBe("object")
        done();
    });
});

test('Generate ECC keypairs. Test convert, encrypt and decrypt', done => {
    var ecckeyoptionsa = {
        encryption: {
            password: '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\',
            cipher: 'aes-256-cbc'
        },
        curve: 'prime256v1',
        rsa_keygen_pubexp: 65537,
        format: 'PKCS8'
    }
    
    openssl.keypair.generateECC(ecckeyoptionsa, function(err, ecc) {
        expect(err).toEqual(false);
        expect(ecc.data.split('\n')[0].trim()).toBe("-----BEGIN ENCRYPTED PRIVATE KEY-----")
    });

    var ecckeyoptionsb = {
        encryption: {
            password: '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\',
            cipher: 'aes-256-cbc'
        },
        curve: 'prime256v1',
        //rsa_keygen_pubexp: 65537,
        format: 'PKCS1'
    }

    openssl.keypair.generateECC({format: 'PKCS1'}, function(err, ecc) {
        expect(err).toEqual(false);
        expect(ecc.data.split('\n')[0].trim()).toBe("-----BEGIN EC PRIVATE KEY-----")
        openssl.keypair.convertToPKCS8({key: ecc.data, password: ecckeyoptionsb.encryption.password}, function(err, pkcs8) {
            expect(err).toEqual(false);
            expect(pkcs8.data.split('\n')[0].trim()).toBe("-----BEGIN ENCRYPTED PRIVATE KEY-----")
            openssl.keypair.convertECCToPKCS1({key: pkcs8.data, encryption: ecckeyoptionsb.encryption}, function(err, pkcs1) {
                expect(err).toEqual(false);
                expect(pkcs1.data.split('\n')[0].trim()).toBe("-----BEGIN EC PRIVATE KEY-----")
                openssl.keypair.convertToPKCS8({key: pkcs1.data, password: ecckeyoptionsb.encryption.password, decrypt: true}, function(err, pkcs8again) {
                    expect(err).toEqual(false);
                    expect(pkcs8again.data.split('\n')[0].trim()).toBe("-----BEGIN PRIVATE KEY-----")
                    openssl.keypair.convertECCToPKCS1({key: pkcs8again.data}, function(err, pkcs1again) {
                        expect(err).toEqual(false);
                        expect(pkcs1again.data.split('\n')[0].trim()).toBe("-----BEGIN EC PRIVATE KEY-----");
                        done();
                    });
                });
            });
        });
    });
});