const node_openssl = require('../index.js');
var openssl = new node_openssl({binpath: 'openssl', debug: false});

openssl.pkcs11.listSlots({modulePath: openssl.binary.pkcs11Tool.getLibDir() + '/x86_64-linux-gnu/libykcs11.so'}, function(err, slots, cmd) {
    if(err) {
        console.log(err);
    } else {
        console.log(slots);
        if(slots.data.length < 1) {
            console.log('no slots found');
        } else {
            openssl.pkcs11.listObjects({
                modulePath: openssl.binary.pkcs11Tool.getLibDir() + '/x86_64-linux-gnu/libykcs11.so',
                slotid: slots.data[0].hexid
            }, function(err, objects) {
                if(err) {
                    console.log(err);
                } else {
                    console.log(objects);
                    openssl.pkcs11.readObject({
                        modulePath: openssl.binary.pkcs11Tool.getLibDir() + '/x86_64-linux-gnu/libykcs11.so',
                        slotid: slots.data[0].hexid,
                        type: 'cert',
                        objectid: objects.data[0]['ID']
                    }, function(err, object) {
                        if(err) {
                            console.log(err);
                        } else {
                            console.log(object.data);
                            openssl.pkcs11.readObject({
                                modulePath: openssl.binary.pkcs11Tool.getLibDir() + '/x86_64-linux-gnu/libykcs11.so',
                                slotid: slots.data[0].hexid,
                                type: 'pubkey',
                                objectid: objects.data[0]['ID']
                            }, function(err, object) {
                                if(err) {
                                    console.log(err);
                                } else {
                                    console.log(object.data);
                                }
                            });
                        }
                    });
                }
            });
        }
    }
});