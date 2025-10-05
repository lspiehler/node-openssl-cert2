var pkcs11ModulePath = '/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so';

module.exports = {
    set: function(path) {
        pkcs11ModulePath = path;
    },
    get: function() {
        return pkcs11ModulePath;
    }
}