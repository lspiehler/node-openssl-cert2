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
        'businessCategory': 'businessCategory'
    }
    
    let dn = [];
    
    try {
        var keys = Object.keys(subjectobj);
        for(let i = 0; i <= keys.length - 1; i++) {
            if(typeof(subjectobj[keys[i]])=='string') {
                dn.push('/' + index[keys[i]] + '=' + subjectobj[keys[i]].split(' ').join('\\ '))
            } else {
                for(let j = 0; j <= subjectobj[keys[i]].length - 1; j++) {
                    dn.push('/' + index[keys[i]] + '=' + subjectobj[keys[i]][j].split(' ').join('\\ '));
                }
            }
        }	
    } catch(e) {
        dn.push('/');
    }
    return dn.join('');
}

module.exports = getDistinguishedName;