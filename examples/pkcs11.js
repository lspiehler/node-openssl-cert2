const node_openssl = require('../index.js');
var openssl = new node_openssl({binpath: 'openssl', debug: true});

openssl.pkcs11.listSlots({modulePath: openssl.binary.pkcs11Tool.getLibDir() + '/x86_64-linux-gnu/libykcs11.so'}, function(err, slots, cmd) {
    if(err) {
        console.log(err);
    } else {
        console.log(slots);
        openssl.pkcs11.listObjects({
            modulePath: openssl.binary.pkcs11Tool.getLibDir() + '/x86_64-linux-gnu/libykcs11.so',
            slotid: slots[0].hexid
        }, function(err, objects) {
            if(err) {
                console.log(err);
            } else {
                console.log(objects);
            }
        });
    }
});