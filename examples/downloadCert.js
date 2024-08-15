const node_openssl = require('../index.js');
var openssl = new node_openssl({binpath: '/opt/openssl32/bin/openssl', debug: false});

let options = {
    hostname: 'norbertboron.com',
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
    ],
    sigalgs: [
        "ECDSA+SHA256",
        "ECDSA+SHA384",
        "ECDSA+SHA512",
        "ed25519",
        "ed448",
        "RSA-PSS+SHA256",
        "RSA-PSS+SHA384",
        "RSA-PSS+SHA512",
        "rsa_pss_rsae_sha256",
        "rsa_pss_rsae_sha384",
        "rsa_pss_rsae_sha512",
        "RSA+SHA256",
        "RSA+SHA384",
        "RSA+SHA512",
        "ECDSA+SHA224",
        "RSA+SHA224",
        "DSA+SHA224",
        "DSA+SHA256",
        "DSA+SHA384",
        "DSA+SHA512"
    ]
}

openssl.x509.getCertFromNetwork(options, function(err, result) {
    if(err) {
        console.log(err);
        console.log(result);
    } else {
        console.log(result);
        console.log(result.data[0]);
        openssl.x509.getOCSPURI(result.data[0], function(err, ocspuri) {
            if(err) {
                console.log(err);
            } else {
                console.log(ocspuri);
            }
        });
    }
});

//https://github.com/openssl/openssl/issues/21296
//OPENSSL_CONF=/path/to/the/config/file/above.cnf

//https://pipeawk.com/index.php/2022/05/19/openssl-enable-legacy-renegotiation/