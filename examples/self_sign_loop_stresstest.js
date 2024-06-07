const node_openssl = require('../index.js');
var openssl = new node_openssl({debug: false});

let rootcarsaoptions = {
    encryption: {
		password: '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\',
		cipher: 'aes-256-cbc'
	},
    format: "PKCS8"
}

var rootcacsroptions = {
	hash: 'sha256',
	days: 240,
	extensions: {
		basicConstraints: {
			critical: true,
			CA: true,
			pathlen: 2
		},
		keyUsage: {
			critical: true,
			usages: [
				'keyCertSign',
				'cRLSign'
			]
		}
	},
	subject: {
		countryName: 'US',
		commonName: [
			'Test Root CA'
		]
	}
}

for(let i = 0; i < 1000; i++) {
    openssl.keypair.generateRSA(rootcarsaoptions, function(err, rootcarsa) {
        if(err) {
            //console.log(err);
        } else {
            //console.log(rootcarsa.data);
            openssl.csr.create({options: rootcacsroptions, key: rootcarsa.data, password: rootcarsaoptions.encryption.password}, function(err, csr) {
                if(err) {
                    //console.log(err);
                } else {
                    openssl.x509.selfSignCSR({options: rootcacsroptions, csr: csr.data, key: rootcarsa.data, password: rootcarsaoptions.encryption.password}, function(err, rootcacert) {
                        if(err) {
                            console.log(err);
                        } else {
                            console.log(rootcacert.data);
                        }
                    });
                }
            });
        }
    });
}