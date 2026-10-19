const index = {
    'C': 'countryName',
    'ST': 'stateOrProvinceName',
    'L': 'localityName',
    'postalCode': 'postalCode',
    'street': 'streetAddress',
    'O': 'organizationName',
    'OU': 'organizationalUnitName',
    'CN': 'commonName',
    'DC': 'domainComponent',
    'SN': 'surname',
    'title': 'title',
    'GN': 'givenName',
    'UID': 'UID',
    'initials': 'initials',
    'generationQualifier': 'generationQualifier',
    'dnQualifier': 'dnQualifier',
    'pseudonym': 'pseudonym',
    'emailAddress': 'emailAddress',
    'jurisdictionL': 'jurisdictionLocalityName',
    'jurisdictionST': 'jurisdictionStateOrProvinceName',
    'jurisdictionC': 'jurisdictionCountryName',
    'serialNumber': 'serialNumber',
    'businessCategory': 'businessCategory'
}

const isHex = function(byte) {
    return (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x46) || (byte >= 0x61 && byte <= 0x66);
}

//splits a name printed with -nameopt esc_2253,esc_ctrl into [{type, value}], one entry per attribute
//RDNs are separated by ', ' and members of a multi-valued RDN by ' + '; separators, '=' and the
//escapes \X and \XX only count outside of escapes, so values may contain any character
const parseName = function(name) {
    var bytes = Buffer.from(name, 'utf8');
    var attributes = [];
    var type = null;
    var current = [];
    var finishAttribute = function() {
        if(type !== null) {
            attributes.push({type: type, value: Buffer.from(current).toString('utf8')});
        }
        type = null;
        current = [];
    }
    for(var i = 0; i <= bytes.length - 1; i++) {
        var byte = bytes[i];
        if(byte == 0x5c && i + 1 <= bytes.length - 1) {
            if(i + 2 <= bytes.length - 1 && isHex(bytes[i + 1]) && isHex(bytes[i + 2])) {
                current.push(parseInt(String.fromCharCode(bytes[i + 1], bytes[i + 2]), 16));
                i += 2;
            } else {
                current.push(bytes[i + 1]);
                i++;
            }
        } else if(byte == 0x3d && type === null) {
            type = Buffer.from(current).toString('utf8');
            current = [];
        } else if(byte == 0x2c && bytes[i + 1] == 0x20) {
            finishAttribute();
            i++;
        } else if(byte == 0x20 && bytes[i + 1] == 0x2b && bytes[i + 2] == 0x20) {
            finishAttribute();
            i += 2;
        } else {
            current.push(byte);
        }
    }
    finishAttribute();
    return attributes;
}

//the subject in the order it is encoded, as [{type, value}] with the same names as getSubject
const getSubjectList = function(certificate) {
    var findsubject = certificate.split('\n');
    var subjectline = null;
    //only the certificate's or request's own Subject line, which OpenSSL prints before any extension
    for(var i = 0; i <= findsubject.length - 1; i++) {
        var match = findsubject[i].match(/^\s*Subject:\s?(.*?)\r?$/);
        if(match) {
            subjectline = match[1];
            break;
        }
    }
    if(subjectline === null || subjectline.trim() == '') {
        return null;
    }
    var attributes = parseName(subjectline);
    for(var i = 0; i <= attributes.length - 1; i++) {
        //attributes without a known name keep the name OpenSSL printed (short name or OID)
        attributes[i].type = index[attributes[i].type] || attributes[i].type;
    }
    return attributes;
}

const getSubject = function(certificate) {
    var normalizesubject = {};
    var subject = {};
    var attributes = getSubjectList(certificate);
    if(attributes === null) {
        return null;
    }
    for(var i = 0; i <= attributes.length - 1; i++) {
        var key = attributes[i].type;
        if(normalizesubject[key]) {
            normalizesubject[key].push(attributes[i].value);
        } else {
            normalizesubject[key] = [attributes[i].value];
        }
    }
    for(var key in normalizesubject) {
        if(normalizesubject[key].length==1) {
            subject[key] = normalizesubject[key][0];
        } else {
            subject[key] = normalizesubject[key];
        }
    }
    return subject;
}

getSubject.parseName = parseName;
getSubject.list = getSubjectList;

module.exports = getSubject;
