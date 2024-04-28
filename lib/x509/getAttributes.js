const getAttributes = function(certificate) {
    var outattrs = {};
    var attrs = certificate.split('\n');
    for(var i = 0; i <= attrs.length - 1; i++) {
        let data = attrs[i].split(':');
        let attr = data[0].trim(' ');
        if(attr=='Public Key Algorithm') {
            outattrs[attr] = data[1].trim(' ');
        } else if(attr=='Signature Algorithm') {
            outattrs[attr] = data[1].trim(' ');
        } else if(attr=='Serial Number') {
            outattrs[attr] = attrs[i+1].trim(' ');
        } else if(attr=='Issuer') {
            outattrs[attr] = data[1].trim(' ');
        } else if(attr=='Subject') {
            outattrs['Subject String'] = data[1].trim(' ');
        } else if(attr.indexOf('Public-Key') >= 0) {
            outattrs['Public-Key'] = data[1].trim(' ').split(' ')[0].substring(1);
        } else if(attr.indexOf('challengePassword') >= 0) {
            outattrs['challengePassword'] = data[1].replace('\r','');
        } else if(attr=='Not After') {
            let parse = data.splice(1);
            var date = parse.join(':').replace('\r\n','').replace('\r','').trim(' ');
            //outattrs[attr] = convertTime(date);
            outattrs[attr] = new Date(date);
        } else if(attr=='Not Before') {
            let parse = data.splice(1);
            var date = parse.join(':').replace('\r\n','').replace('\r','').trim(' ');
            //console.log(new Date(date));
            //outattrs[attr] = convertTime(date);
            outattrs[attr] = new Date(date);
        }
    }
    var lastline = attrs[attrs.length - 2];
    if(lastline) {
        if(lastline.indexOf('Fingerprint') >= 0) {
            outattrs['Thumbprint'] = lastline.split('=')[1].replace('\r\n','').replace('\r','').trim(' ');
        }
    }
    return getAttributes;
}

module.exports = getAttributes;