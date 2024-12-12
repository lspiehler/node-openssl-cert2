const trimSubjectAttrs = function(values) {
    var trimmed = []
    for(var i = 0; i <= values.length - 1; i++) {
        trimmed.push(values[i].trim());
    }
    return trimmed;
}

const getSubject = function(certificate) {
    var normalizesubject = {};
    var subject = {};
    var index = {
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
    var subjectstr = 'Subject: '
    var findsubject = certificate.split('\n');
    for(var i = 0; i <= findsubject.length - 1; i++) {
        if(findsubject[i].indexOf(subjectstr) >= 0) {
            var subjectline = findsubject[i].substr(findsubject[i].indexOf(subjectstr) + subjectstr.length);
            //console.log(subjectline);
            //console.log(subjectline.replace(/\//g, ', '));
            //console.log(subjectline.split('='));
            var subjectarr = subjectline.replace(/\//g, ', ')
            var untrimmedsubject = subjectarr.split('=');
            var splitsubject = trimSubjectAttrs(untrimmedsubject);
            //if subject is blank return now
            if(splitsubject.length <= 1 && splitsubject[0]=='') {
                return null;
            }
            if(splitsubject[0].split(', ').length > 2) {
                //console.log(splitsubject[j].split(', '));
                value = splitsubject[1].split(', ').slice(0, -1).join(', ');
                type = splitsubject[0]
            } else {
                value = splitsubject[1].split(', ')[0];
                type = splitsubject[0]
            }
            normalizesubject[index[type]] = [value];
            for(var j = 1; j <= splitsubject.length - 2; j++) {
                var type;
                var value;
                if(splitsubject[j + 1].split(', ').length > 2) {
                    //console.log(splitsubject[j]);
                    //console.log(splitsubject[j].split(', '));
                    value = splitsubject[j + 1].split(', ').slice(0, -1).join(', ');
                    type = splitsubject[j].split(', ').pop();
                    //console.log(type);
                    //console.log(value);
                } else {
                    value = splitsubject[j + 1].split(', ')[0];
                    type = splitsubject[j].split(', ')[splitsubject[j].split(', ').length - 1];
                    //console.log(type);
                }
                //console.log(type);
                if(normalizesubject[index[type]]) {
                normalizesubject[index[type]].push(value);
                } else {
                    normalizesubject[index[type]] = [value];
                }
            }
        }
    }
    //console.log(normalizesubject);
    for(var key in normalizesubject) {
        //console.log(typeof(normalizesubject[key]));
        if(normalizesubject[key].length==1) {
            subject[key] = normalizesubject[key][0].replace(/\"/g, '');
        } else {
            //subject[key] = normalizesubject[key].replace(/\"/g, '');
            subject[key] = [];
            for(let i = 0; i <= normalizesubject[key].length - 1; i++) {
                subject[key].push(normalizesubject[key][i].replace(/\"/g, ''));
            }
        }
    }
    //console.log(subject);
    return subject;
}

module.exports = getSubject;