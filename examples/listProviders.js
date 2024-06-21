const node_openssl = require('../index.js');
var openssl = new node_openssl({binpath: '/opt/openssl32/bin/openssl', debug: false});

openssl.providers.get(function(err, providers) {
    if(err) {
        console.log(err);
    } else {
        console.log(providers);
        openssl.providers.get(function(err, providers) {
            if(err) {
                console.log(err);
            } else {
                console.log(providers);
            }
        });
    }
});