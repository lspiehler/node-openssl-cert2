const node_openssl = require('../index.js');
var openssl = new node_openssl();
const config = require('../lib/config');

//SoftHSM crashes at exit on OpenSSL 3.5 without the no-deinit quirk (lib/config/pkcs11ModuleQuirks.js); signing with
//it on a token is tested in softhsm.test.js, whose tests run one after another on one token store
const lib = '/usr/lib/softhsm/libsofthsm2.so';

test('Only SoftHSM gets the no-deinit quirk', () => {
    expect(config.pkcs11ModuleQuirks.lines(lib)).toEqual(['pkcs11-module-quirks = no-deinit']);
    expect(config.pkcs11ModuleQuirks.lines('/usr/lib/x86_64-linux-gnu/libykcs11.so')).toEqual([]);
    expect(config.pkcs11ModuleQuirks.lines('/usr/local/lib/libkmsp11.so')).toEqual([]);
    expect(config.pkcs11ModuleQuirks.providerConfig('/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so')).toBe(false);
});

test('The provider config for SoftHSM gives the quirk without activating the provider', () => {
    let conf = config.pkcs11ModuleQuirks.providerConfig(lib);
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
        config.generate({...options, module: lib}, false, false, version, function(err, req) {
            expect(err).toEqual(false);
            expect(req).toContain('pkcs11-module-quirks = no-deinit');
            config.generate({...options, module: '/usr/lib/x86_64-linux-gnu/libykcs11.so'}, false, false, version, function(err, req) {
                expect(err).toEqual(false);
                expect(req.join('\n')).not.toContain('pkcs11-module-quirks');
                done();
            });
        });
    });
});
