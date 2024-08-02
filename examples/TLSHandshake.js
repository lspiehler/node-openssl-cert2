const node_openssl = require('../index.js');
var openssl = new node_openssl({binpath: '/opt/openssl32/bin/openssl', debug: false});

let options = {
    hostname: 'pq.cloudflareresearch.com',
    port: 443,
    starttls: false,
    protocol: 'https',
    trace: true,
    groups: [
        "x25519_kyber768",
        "p256_kyber768"
    ]
}

openssl.x509.TLSHandshake(options, function(err, result) {
    if(err) {
        console.log(err);
        console.log(result);
    } else {
        console.log(result);
        console.log(result.data);
    }
});

//https://github.com/openssl/openssl/issues/21296
//OPENSSL_CONF=/path/to/the/config/file/above.cnf

//https://pipeawk.com/index.php/2022/05/19/openssl-enable-legacy-renegotiation/