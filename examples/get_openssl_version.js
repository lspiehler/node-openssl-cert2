const node_openssl = require('../index.js');
var openssl = new node_openssl({binpath: "C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe"});

openssl.binary.getVersion(function(err, version) {
    if(err) {
        console.log(err);
    } else {
        console.log(version);
    }
});