const parseExtensions = require('./parseExtensions');

const getv3Attributes = function(certificate, originalcert, callback) {
    var parsedextensions = {};
    var x509v3 = certificate.split('\n');
    //console.log(x509v3);
    for(var i = 0; i <= x509v3.length - 1; i++) {
        if(x509v3[i].indexOf('X509v3') >= 0 || x509v3[i].indexOf('CT Precertificate SCTs') >= 0 || x509v3[i].indexOf('Authority Information Access') >= 0 || x509v3[i].indexOf('TLS Feature') >= 0 ) {
            var ext = x509v3[i].split(':');
            var extname = ext[0].replace('X509v3','').trim();
            //console.log(ext);
            var critical = false;
            if(ext[1].replace('\r\n').replace('\n').trim()=='critical') {
                critical = true;
                //console.log('critical');
                parsedextensions[extname] = { "critical": critical, "content": []};
            } else {
                parsedextensions[extname] = { "content": []};
            }
            //console.log(i + ' - ' + extname + ' - ' + critical);
        } else {
            if(parsedextensions[extname]) {
                parsedextensions[extname].content.push(x509v3[i].trim());
            }
        }
    }
    
    //return null if there are no x509v3 extensions
    parseExtensions(originalcert, parsedextensions, false, 0, function(err, extensions) {
        if (Object.keys(extensions).length <= 0) {
            callback(null, null);
        } else {
            callback(null, extensions);
        }
    });
}

module.exports = getv3Attributes;