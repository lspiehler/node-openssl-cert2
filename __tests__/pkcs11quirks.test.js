const node_openssl = require('../index.js');
const fs = require('fs');
var openssl = new node_openssl();

//SoftHSM crashes at exit on OpenSSL 3.5 without the no-deinit quirk (lib/config/pkcs11ModuleQuirks.js)
const lib = '/usr/lib/softhsm/libsofthsm2.so';
const label = 'quirks';
const pin = '123456';

test('Only SoftHSM gets the no-deinit quirk', () => {
    expect(require('../lib/config').pkcs11ModuleQuirks.lines(lib)).toEqual(['pkcs11-module-quirks = no-deinit']);
    expect(require('../lib/config').pkcs11ModuleQuirks.lines('/usr/lib/x86_64-linux-gnu/libykcs11.so')).toEqual([]);
    expect(require('../lib/config').pkcs11ModuleQuirks.lines('/usr/local/lib/libkmsp11.so')).toEqual([]);
    expect(require('../lib/config').pkcs11ModuleQuirks.providerConfig('/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so')).toBe(false);
});

test('The provider config for SoftHSM gives the quirk without activating the provider', () => {
    let conf = require('../lib/config').pkcs11ModuleQuirks.providerConfig(lib);
    expect(conf).toContain('[pkcs11_sect]');
    expect(conf).toContain('pkcs11-module-quirks = no-deinit');
    //-provider pkcs11 activates it, with the module from PKCS11_PROVIDER_MODULE
    expect(conf).not.toContain('activate');
    expect(conf).not.toContain('pkcs11-module-path');
});

test('A generated config gives SoftHSM the quirk, other modules none', done => {
    let options = {hash: 'sha256', days: 1, subject: {commonName: ['quirks']}};
    openssl.binary.openssl.getVersion(function(err, version) {
        expect(err).toEqual(false);
        if(parseInt(version.substring(0, 1)) < 3) {
            done();
            return;
        }
        require('../lib/config').generate({...options, module: lib}, false, false, version, function(err, req) {
            expect(err).toEqual(false);
            expect(req).toContain('pkcs11-module-quirks = no-deinit');
            require('../lib/config').generate({...options, module: '/usr/lib/x86_64-linux-gnu/libykcs11.so'}, false, false, version, function(err, req) {
                expect(err).toEqual(false);
                expect(req.join('\n')).not.toContain('pkcs11-module-quirks');
                done();
            });
        });
    });
});

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

//smime.sign loads the pkcs11 provider on the command line, so it gets the quirk through OPENSSL_CONF
//(softhsm.test.js covers the generated configs: selfSignCSR, CASignCSR, crl.generate)
//On Ubuntu 24.04 (OpenSSL 3.0.13, pkcs11-provider 0.3) openssl cms -sign with SoftHSM hangs with or without the
//quirk, so this test times out there; CI runs Ubuntu 26.04, where it passes.
test('Sign CMS with a key on a softhsm2 token', done => {
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
                    openssl.pkcs11.generateKeyPair({
                        modulePath: lib,
                        label: label,
                        slotid: softhsm.data.hexid,
                        objectid: '01',
                        keytype: 'EC:prime256v1',
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
                                objectid: '01',
                                type: 'private'
                            })
                        }
                        openssl.x509.selfSignCSR({
                            options: {hash: 'sha256', days: 1, subject: {commonName: ['CMS signer']}},
                            pkcs11: pkcs11
                        }, function(err, cert) {
                            expect(err).toEqual(false);
                            openssl.smime.sign({data: 'signed on a token', cert: cert.data, pkcs11: pkcs11}, function(err, signed) {
                                expect(err).toEqual(false);
                                expect(signed.data).toContain('-----BEGIN CMS-----');
                                expect(signed.command[0]).not.toContain(pin);
                                openssl.pkcs11.listSlots({modulePath: lib}, function(err, slots) {
                                    deleteTestSlotIfExists(slots, function(err, result) {
                                        expect(err).toEqual(false);
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
}, 60000);
