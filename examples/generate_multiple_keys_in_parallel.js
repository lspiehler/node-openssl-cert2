const node_openssl = require('../index.js');
var openssl = new node_openssl({debug: false});

for(let i = 0; i < 100; i++) {
    openssl.keypair.generateRSA({}, function(err, rsa) {
        if(err) {
            console.log(err);
        } else {
            console.log(rsa.data);
        }
    });
}