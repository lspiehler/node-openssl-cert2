const node_openssl = require('../index.js');
const crypto = require('crypto');
var openssl = new node_openssl();

const password = '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\';
//any bytes: the caller builds the TBS certificate, signTBS only signs it
const tbs = crypto.randomBytes(300);

function keypair(type, options, encrypted) {
    let keys = crypto.generateKeyPairSync(type, options);
    let exportoptions = {type: 'pkcs8', format: 'pem'};
    if(encrypted) {
        exportoptions.cipher = 'aes-256-cbc';
        exportoptions.passphrase = password;
    }
    return {
        key: keys.privateKey.export(exportoptions),
        publicKey: keys.publicKey
    }
}

test('Sign TBS bytes with an encrypted RSA key', done => {
    let rsa = keypair('rsa', {modulusLength: 2048}, true);
    openssl.x509.signTBS({data: tbs, key: rsa.key, password: password, hash: 'sha256'}, function(err, signature) {
        expect(err).toEqual(false);
        expect(signature.data).toBeInstanceOf(Buffer);
        expect(crypto.verify('sha256', tbs, rsa.publicKey, signature.data)).toBe(true);
        expect(signature.command[0]).toContain('-passin pass:hidden');
        done();
    });
});

test('Sign TBS bytes with an encrypted ECDSA key', done => {
    let ecc = keypair('ec', {namedCurve: 'P-384'}, true);
    openssl.x509.signTBS({data: tbs, key: ecc.key, password: password, hash: 'sha384'}, function(err, signature) {
        expect(err).toEqual(false);
        //DER ECDSA-Sig-Value, as it goes into the certificate
        expect(crypto.verify('sha384', tbs, ecc.publicKey, signature.data)).toBe(true);
        done();
    });
});

test('Sign TBS bytes with an encrypted Ed25519 key', done => {
    let ed = keypair('ed25519', {}, true);
    openssl.x509.signTBS({data: tbs, key: ed.key, password: password}, function(err, signature) {
        expect(err).toEqual(false);
        expect(signature.data.length).toBe(64);
        expect(crypto.verify(null, tbs, ed.publicKey, signature.data)).toBe(true);
        done();
    });
});

test('Sign TBS bytes with an unencrypted key', done => {
    let ecc = keypair('ec', {namedCurve: 'P-256'}, false);
    openssl.x509.signTBS({data: tbs, key: ecc.key, hash: 'sha256'}, function(err, signature) {
        expect(err).toEqual(false);
        expect(crypto.verify('sha256', tbs, ecc.publicKey, signature.data)).toBe(true);
        done();
    });
});

test('Signing TBS bytes with the wrong password fails without a signature', done => {
    let ecc = keypair('ec', {namedCurve: 'P-256'}, true);
    openssl.x509.signTBS({data: tbs, key: ecc.key, password: 'wrong', hash: 'sha256'}, function(err, signature) {
        expect(err).toBeTruthy();
        expect(signature.data).toBe(false);
        expect(signature.command[0]).not.toContain('wrong');
        done();
    });
});

test('signTBS refuses a hash that is not a digest name, and missing data, without running openssl', done => {
    let ecc = keypair('ec', {namedCurve: 'P-256'}, false);
    openssl.x509.signTBS({data: tbs, key: ecc.key, hash: 'sha256 -out /tmp/leak.bin'}, function(err, signature) {
        expect(err).toBe('Invalid hash: sha256 -out /tmp/leak.bin');
        expect(signature).toEqual({command: [], data: false});
        openssl.x509.signTBS({key: ecc.key, hash: 'sha256'}, function(err, signature) {
            expect(err).toMatch(/^Invalid data/);
            expect(signature).toEqual({command: [], data: false});
            done();
        });
    });
});

//signing with a key on a token is tested in softhsm.test.js, whose tests run one after another on one token store
