const path = require('path');
const pkcs11ModulePath = require('./pkcs11ModulePath');

// SoftHSM 2.6 crashes (SIGSEGV) when pkcs11-provider unloads it as openssl exits, after the output is written, on
// OpenSSL 3.5 with pkcs11-provider 1.x (Ubuntu 26.04: every signature). SoftHSM uses OpenSSL itself, and its
// C_Finalize runs after OpenSSL has freed what it still uses (softhsm/SoftHSMv2 issues 729 and 780; not fixed in
// 2.6.1). We treat the crash as a failure, so SoftHSM couldn't sign at all there.
// pkcs11-provider's no-deinit quirk skips C_Finalize. That is safe for SoftHSM: every openssl process here is
// short-lived, so the OS reclaims what C_Finalize would free; SoftHSM writes token objects when they are created, not
// at C_Finalize; and there is no card whose login state could outlive the process. It is only set for SoftHSM:
// skipping C_Finalize on a smart card (e.g. a YubiKey) leaves releasing the card to pcscd, which we haven't verified.
// pkcs11-provider 0.3 (Ubuntu 24.04) accepts the quirk too.
var isSoftHSM = function(modulePath) {
    return path.basename(String(modulePath)) == 'libsofthsm2.so';
}

// the pkcs11 provider config lines for this PKCS#11 module, for a [pkcs11_sect] the caller writes
var lines = function(modulePath) {
    if(isSoftHSM(modulePath)) {
        return ['pkcs11-module-quirks = no-deinit'];
    } else {
        return [];
    }
}

// for commands that load the pkcs11 provider on the command line (-provider pkcs11), where there is no config of
// ours: a config that only gives the provider its quirks, without activating it, so -provider pkcs11 loads it with
// them; false when the module needs none. Pass its path in OPENSSL_CONF.
var providerConfig = function(modulePath) {
    let quirks = lines(modulePath);
    if(quirks.length == 0) {
        return false;
    }
    return [
        'openssl_conf = openssl_init',
        '[openssl_init]',
        'providers = provider_sect',
        '[provider_sect]',
        'pkcs11 = pkcs11_sect',
        '[pkcs11_sect]',
        'module = ' + pkcs11ModulePath.get()
    ].concat(quirks).concat(['']).join('\n');
}

module.exports = {
    lines: lines,
    providerConfig: providerConfig
}
