const node_openssl = require('../index.js');
var openssl = new node_openssl({binpath: '/opt/openssl32/bin/openssl', debug: false});

//const algorithm = 'sphincsshake128fsimple'
//const algorithm = 'mldsa44'
//const algorithm = 'p256_sphincssha2128fsimple'
const algorithm = 'dilithium5'
//const algorithm = 'falcon512'

let options = {
    algorithm: algorithm
}

openssl.keypair.generateOQSKey(options, function(err, key) {
    if(err) {
        console.log(err);
    } else {
        console.log(key);
    }
});