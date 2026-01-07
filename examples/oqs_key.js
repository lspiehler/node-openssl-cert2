const node_openssl = require('../index.js');
var openssl = new node_openssl({});

//const algorithm = 'sphincsshake128fsimple'
// const algorithm = 'mldsa44'
const algorithm = 'slh-dsa-sha2-128f'
//const algorithm = 'p256_sphincssha2128fsimple'
// const algorithm = 'sphincsshake192fsimple'
//const algorithm = 'falcon512'

let options = {
    algorithm: algorithm
}

openssl.keypair.generateOQSKey(options, function(err, key) {
    if(err) {
        console.log(err);
    } else {
        console.log(key.data);
    }
});