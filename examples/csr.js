const node_openssl = require('../index.js');
var openssl = new node_openssl({debug: false, binpath: "C:/Program Files/OpenSSL-Win64/bin/openssl.exe"});

let rsaoptionsa = {
    encryption: {
		password: '!@#$%^&*()_+|}{:"?><1234567890-=][;/.,\\',
		cipher: 'aes-256-cbc'
	},
    format: "PKCS1"
}

var csroptions = {
	hash: 'sha512',
	days: 240,
	/*requestAttributes: {
		challengePassword: "this is my challenge passphrase"
	},
	string_mask: "nombstr",*/
	extensions: {
		customOIDs: [
			{
				OID: '1.3.6.1.4.1.311.20.2',
				value: 'ASN1:PRINTABLESTRING:Test Template'
			}
		],
		tlsfeature: ['status_request'],
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
				'clientAuth',
				'ipsecIKE',
				'ipsecUser',
				'ipsecTunnel',
				'ipsecEndSystem'
			]	
		},
		SANs: {
			DNS: [
				'certificatetools.com',
				'www.certificatetools.com'
			]
		}
	},
	subject: {
		countryName: 'US',
		stateOrProvinceName: 'Louisiana',
		localityName: 'Slidell',
		postalCode: '70458',
		streetAddress: '1001 Gause Blvd.',
		organizationName: 'SMH',
		organizationalUnitName: [
				'IT'
		],
		commonName: [
				'certificatetools.com',
				'www.certificatetools.com'
		],
		emailAddress: 'lyas.spiehler@slidellmemorial.org'
	}

}

openssl.keypair.generateRSA(rsaoptionsa, function(err, rsa) {
    if(err) {
        console.log(err);
    } else {
        console.log(rsa.data);
        openssl.csr.create({options: csroptions, key: rsa.data, password: rsaoptionsa.encryption.password}, function(err, csr) {
            if(err) {
                console.log(err);
            } else {
                console.log(csr.data);
            }
        });
    }
});