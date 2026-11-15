const node_openssl = require('../index.js');
const crypto = require('crypto');
const fs = require('fs');
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

const lib = '/usr/lib/softhsm/libsofthsm2.so';
const label = 'signtbs';
const pin = '123456';

const deleteTestSlotIfExists = function(slots, callback) {
    let foundtestslot = -1;
    for(let i = 0; i < slots.data.length; i++) {
        if(slots.data[i]['token label']==label) {
            foundtestslot = i;
            break;
        }
    }
    if(foundtestslot >= 0) {
        openssl.softhsm2.deleteSlot({serial: slots.data[foundtestslot]['serial num']}, function(err, result) {
            callback(err, result);
        });
    } else {
        callback(false, false);
    }
}

test('Sign TBS bytes with RSA and ECDSA keys on a softhsm2 token', done => {
    fs.stat(lib, function(err, stat) {
        if(err) {
            done();
            return;
        }
        openssl.pkcs11.listSlots({modulePath: lib}, function(err, slots) {
            expect(err).toEqual(false);
            deleteTestSlotIfExists(slots, function(err, result) {
                expect(err).toEqual(false);
                openssl.softhsm2.createSlot({modulePath: lib, label: label, pin: pin, sopin: pin}, function(err, softhsm) {
                    expect(err).toEqual(false);
                    let keys = [
                        {objectid: '01', keytype: 'rsa:2048', hash: 'sha256'},
                        {objectid: '02', keytype: 'EC:prime256v1', hash: 'sha256'}
                    ];
                    let signNext = function(index) {
                        if(index > keys.length - 1) {
                            openssl.pkcs11.listSlots({modulePath: lib}, function(err, slots) {
                                deleteTestSlotIfExists(slots, function(err, result) {
                                    expect(err).toEqual(false);
                                    done();
                                });
                            });
                            return;
                        }
                        openssl.pkcs11.generateKeyPair({
                            modulePath: lib,
                            label: label,
                            slotid: softhsm.data.hexid,
                            objectid: keys[index].objectid,
                            keytype: keys[index].keytype,
                            pin: pin,
                            loginType: "User",
                            serial: softhsm.data['serial num'],
                            signpin: pin
                        }, function(err, kpresult) {
                            expect(err).toEqual(false);
                            let pkcs11 = {
                                modulePath: lib,
                                pin: pin,
                                uri: openssl.common.encodePKCS11URI({
                                    serial: softhsm.data['serial num'],
                                    objectid: keys[index].objectid,
                                    type: 'private'
                                })
                            }
                            //the token's public key, from a certificate it signed
                            openssl.x509.selfSignCSR({
                                options: {hash: 'sha256', days: 1, subject: {commonName: ['signTBS test']}},
                                pkcs11: pkcs11
                            }, function(err, cert) {
                                expect(err).toEqual(false);
                                let publicKey = new crypto.X509Certificate(cert.data).publicKey;
                                openssl.x509.signTBS({data: tbs, hash: keys[index].hash, pkcs11: pkcs11}, function(err, signature) {
                                    expect(err).toEqual(false);
                                    expect(crypto.verify(keys[index].hash, tbs, publicKey, signature.data)).toBe(true);
                                    expect(signature.command[0]).toContain('-passin pass:hidden');
                                    expect(signature.command[0]).not.toContain(pin);
                                    signNext(index + 1);
                                });
                            });
                        });
                    }
                    signNext(0);
                });
            });
        });
    });
}, 60000);
