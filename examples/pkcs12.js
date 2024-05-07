const node_openssl = require('../index.js');
var openssl = new node_openssl({debug: false});
const fs = require('fs');

var csroptions = {
	hash: 'sha256',
	extensions: {
		basicConstraints: {
			critical: true,
			CA: true,
			pathlen: 1
		},
		keyUsage: {
			critical: true,
			usages: [
				'digitalSignature',
				'keyEncipherment'
			]
		},
		extendedKeyUsage: {
			critical: true,
			usages: [
				'serverAuth',
				'clientAuth'
			]	
		},
		SANs: {
			DNS: ['certificatetools.com']
		}
	},
	subject: {
		countryName: 'US',
		commonName: ['certificatetools.com']
	}

}

openssl.keypair.generateRSA({}, function(err, rsa) {
    if(err) {
        console.log(err);
    } else {
        console.log(rsa.data);
        openssl.csr.create({options: csroptions, key: rsa.data}, function(err, csr) {
            if(err) {
                console.log(err);
            } else {
                console.log(csr.data);
				openssl.x509.selfSignCSR({options: csroptions, csr: csr.data, key: rsa.data}, function(err, cert) {
					if(err) {
						console.log(err);
					} else {
                        openssl.x509.createPKCS12({
                            cert: cert.data,
                            key: rsa.data,
                            //pkcs12pass: 'test'
                        }, function(err, pkcs12) {
                            if(err) {
                                console.log(err);
                            } else {
                                fs.writeFile('./test_files/pkcs12.pfx', pkcs12.data, function(err) {

                                });
                                console.log(pkcs12.data);
                            }
                        });
                    }
                });
            }
        });
    }
});