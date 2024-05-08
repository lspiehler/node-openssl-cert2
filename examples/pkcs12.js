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
                            pkcs12pass: 'test'
                        }, function(err, pkcs12) {
                            if(err) {
                                console.log(err);
                            } else {
                                fs.writeFile('./test_files/pkcs12.pfx', pkcs12.data, function(err) {

                                });
                                openssl.x509.getKeyFromPKCS12({pkcs12: pkcs12.data, password: 'test'}, function(err, key) {
                                    if(err) {
                                        console.log(err);
                                        console.log(key);
                                    } else {
                                        console.log(key.data);
                                        openssl.x509.getCertFromPKCS12({pkcs12: pkcs12.data, password: 'test'}, function(err, cert) {
                                            if(err) {
                                                console.log(err);
                                                console.log(cert);
                                            } else {
                                                console.log(cert.data);
                                                openssl.x509.getChainFromPKCS12({pkcs12: pkcs12.data, password: 'test'}, function(err, chain) {
                                                    if(err) {
                                                        console.log(err);
                                                        //console.log(chain);
                                                    } else {
                                                        console.log(chain.data);
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
            }
        });
    }
});