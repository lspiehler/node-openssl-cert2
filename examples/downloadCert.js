const node_openssl = require('../index.js');
var openssl = new node_openssl({binpath: '/opt/openssl32/bin/openssl', debug: false});

let options = {
    hostname: 'slashdot.org',
    port: 443,
    starttls: false,
    protocol: 'https',
    groups: [
        "x25519",
        "secp256r1",
        "x448",
        "secp521r1",
        "secp384r1",
        "ffdhe2048",
        "ffdhe3072",
        "ffdhe4096",
        "ffdhe6144",
        "ffdhe8192",
        "prime256v1"
    ]
}

openssl.x509.getCertFromNetwork(options, function(err, result) {
    if(err) {
        console.log(err);
    } else {
        console.log(result.data[1]);
    }
});