//names are printed with -nameopt esc_2253,esc_ctrl so getSubject can parse them; remove the
//escapes here so Issuer and Subject String stay as OpenSSL prints them with -nameopt utf8
const unescapeName = function(name) {
    //esc_ctrl only hex-escapes control characters, so each \XX is a single character
    return name.replace(/\\([0-9A-Fa-f]{2}|[\s\S])/g, function(escape, value) {
        if(value.length == 2) {
            return String.fromCharCode(parseInt(value, 16));
        } else {
            return value;
        }
    });
}

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
            outattrs[attr] = unescapeName(data[1].trim(' '));
        } else if(attr=='Subject') {
            outattrs['Subject String'] = unescapeName(data[1].trim(' '));
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
    return outattrs;
}

module.exports = getAttributes;