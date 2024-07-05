const node_openssl = require('../index.js');
var openssl = new node_openssl({binpath: '/opt/openssl32/bin/openssl', debug: false});

let dilithium2encrypted = {
    algorithm: 'dilithium2',
    encryption: {
        cipher: 'des3',
        password: 'hello!!!'
    }
}

let dilithium3encrypted = {
    algorithm: 'dilithium3',
    encryption: {
        cipher: 'aes256',
        password: 'hello!!!'
    }
}

let dilithium3unencrypted = {
    algorithm: 'dilithium3'
}

openssl.keypair.generateOQSKey({}, function(err, key) {
    if(err) {
        console.log(err);
        //console.log(key);
    } else {
        console.log(key);
        openssl.keypair.generateOQSKey(dilithium2encrypted, function(err, key) {
            if(err) {
                console.log(err);
                console.log(key);
            } else {
                console.log(key);
                openssl.keypair.generateOQSKey(dilithium3encrypted, function(err, dilithium3key) {
                    if(err) {
                        console.log(err);
                        console.log(key);
                    } else {
                        console.log(dilithium3key);
                        openssl.keypair.generateOQSKey(dilithium3unencrypted, function(err, key) {
                            if(err) {
                                console.log(err);
                                console.log(key);
                            } else {
                                console.log(key);
                                console.log(dilithium3key.data);
                                openssl.keypair.importOQSKey({key: dilithium3key.data, password: dilithium3encrypted.encryption.password}, function(err, unencryptedkey) {
                                    if(err) {
                                        console.log(err);
                                        console.log(key);
                                    } else {
                                        console.log(unencryptedkey.data);
                                    }
                                });
                            }
                        });
                    }
                });
            }
        });
    }
});