const node_openssl = require('../index.js');
var openssl = new node_openssl({binpath: 'openssl', debug: true});

let rsaoptions = {
    encryption: {
        password: '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\',
        cipher: 'aes-256-cbc'
    },
    format: "PKCS1"
}

openssl.keypair.generateRSA(rsaoptions, function(err, rsa) {
    if(err) {
        console.log(err);
    } else {
        console.log(rsa.data);
    }
});