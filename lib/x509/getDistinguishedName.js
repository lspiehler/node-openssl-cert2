const getDistinguishedName = function(subjectobj) {
    var index = {
        'countryName': 'C',
        'stateOrProvinceName': 'ST',
        'localityName': 'L',
        'postalCode': 'postalCode',
        'streetAddress': 'street',
        'organizationName': 'O',
        'organizationalUnitName': 'OU',
        'commonName': 'CN',
        'emailAddress': 'emailAddress',
        'jurisdictionLocalityName': 'jurisdictionL',
        'jurisdictionStateOrProvinceName': 'jurisdictionST',
        'jurisdictionCountryName': 'jurisdictionC',
        'serialNumber': 'serialNumber',
        'businessCategory': 'businessCategory',
        'domainComponent': 'DC',
        'surname': 'SN',
        'title': 'title',
        'givenName': 'GN',
        'UID': 'UID',
        'initials': 'initials',
        'generationQualifier': 'generationQualifier',
        'dnQualifier': 'dnQualifier',
        'pseudonym': 'pseudonym',
        'organizationIdentifier': 'organizationIdentifier',
        'unstructuredName': 'unstructuredName',
        'unstructuredAddress': 'unstructuredAddress'
    }
    
    //-subj treats '/' and '+' as separators and '\\' as an escape; spaces are escaped because the
    //command is split on unescaped spaces before it runs
    const escapeValue = function(value) {
        return value.replace(/[\\\/+]/g, '\\$&').split(' ').join('\\ ');
    }

    let dn = [];

    //an ordered list [{type, value}] (as from getSubjectList) is written in its own order
    if(Array.isArray(subjectobj)) {
        for(let i = 0; i <= subjectobj.length - 1; i++) {
            if(!subjectobj[i] || !index.hasOwnProperty(subjectobj[i].type) || typeof(subjectobj[i].value) != 'string') {
                return false;
            }
            dn.push('/' + index[subjectobj[i].type] + '=' + escapeValue(subjectobj[i].value));
        }
        if(dn.length == 0) {
            dn.push('/');
        }
    } else {
        try {
            var keys = Object.keys(subjectobj);
            for(let i = 0; i <= keys.length - 1; i++) {
                if(typeof(subjectobj[keys[i]])=='string') {
                    dn.push('/' + index[keys[i]] + '=' + escapeValue(subjectobj[keys[i]]))
                } else {
                    for(let j = 0; j <= subjectobj[keys[i]].length - 1; j++) {
                        dn.push('/' + index[keys[i]] + '=' + escapeValue(subjectobj[keys[i]][j]));
                    }
                }
            }	
        } catch(e) {
            dn.push('/');
        }
    }
    //a trailing backslash would escape the space before the next option; OpenSSL ignores a final '/'
    if(dn.length > 0 && dn[dn.length - 1].charAt(dn[dn.length - 1].length - 1) == '\\') {
        dn.push('/');
    }
    return dn.join('');
}

module.exports = getDistinguishedName;