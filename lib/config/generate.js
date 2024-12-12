const generatePolicyConfig = function(policies) {
    let policyconfig = [];
    for(let i = 0; i <= policies.length - 1; i++) {
        policyconfig.push('[ polsect' + i + ' ]');
        policyconfig.push('policyIdentifier = ' + policies[i].policyIdentifier);
        if(policies[i].CPS) {
            if(typeof(policies[i].CPS)=='string') {
                policyconfig.push('CPS="' + policies[i].CPS +'"');
            } else {
                for(let j = 0; j <= policies[i].CPS.length - 1; j++) {
                    policyconfig.push('CPS.' + j + '="' + policies[i].CPS[j] +'"');
                }
            }
        }
        if(policies[i].userNotice) {
            for(let j = 0; j <= policies[i].userNotice.length - 1; j++) {
                policyconfig.push('userNotice.' + j + '=@notice' + j);
            }
            for(let j = 0; j <= policies[i].userNotice.length - 1; j++) {
                policyconfig.push('[ notice' + j + ' ]');
                if(policies[i].userNotice[j].explicitText) {
                    policyconfig.push('explicitText="' + policies[i].userNotice[j].explicitText + '"');
                }
                if(policies[i].userNotice[j].organization) {
                    policyconfig.push('organization="' + policies[i].userNotice[j].organization + '"');
                }
                if(policies[i].userNotice[j].noticeNumbers) {
                    policyconfig.push('noticeNumbers=' + policies[i].userNotice[j].noticeNumbers.join(','));
                }
            }
        }
    }
    /*policyconfig.push('[ polsect0 ]');
    policyconfig.push('policyIdentifier = 2.16.840.1.114412.2.1');
    policyconfig.push('CPS.1="https://certificatetools.com"');
    policyconfig.push('[ polsect1 ]');
    policyconfig.push('policyIdentifier = 2.23.140.1.2.1');*/
    
    //console.log(policyconfig);
    return policyconfig;
}

const generate = function(options, cert, cadir, callback) {
    options.hash = typeof options.hash !== 'undefined' ? options.hash : 'sha256';
    const validopts = [
        'hash',
        'subject'
    ];
    const validkeyusage = [
        'keyCertSign', //CA Only
        'cRLSign', //CA Only
        'digitalSignature',
        'nonRepudiation',
        'keyEncipherment',
        'dataEncipherment',
        'keyAgreement',
        'encipherOnly',
        'decipherOnly'
    ]
    
    const validtlsfeature = [
        'status_request'
    ]
    
    const validrequestattribute = [
        'challengePassword',
        'challengePassword_min',
        'challengePassword_max',
        'unstructuredName'
    ]

    const validextkeyusage = [
        'serverAuth',
        'clientAuth',
        'codeSigning',
        'emailProtection',
        'timeStamping',
        'OCSPSigning',
        'msCodeInd',
        'msCodeCom',
        'msCTLSign',
        'msEFS',
        'ipsecIKE',
        'ipsecEndSystem',
        'ipsecTunnel',
        'ipsecUser',
        '1.3.6.1.4.1.311.20.2.1'
    ]
    
    const validsubject = [
        'countryName',
        'domainComponent',
        'surname',
        'serialNumber',
        'title',
        'givenName',
        'stateOrProvinceName',
        'localityName',
        'postalCode',
        'streetAddress',
        'UID',
        'initials',
        'generationQualifier',
        'dnQualifier',
        'pseudonym',
        'organizationName',
        'organizationalUnitName',
        'commonName',
        'emailAddress',
        'jurisdictionCountryName',
        'jurisdictionStateOrProvinceName',
        'jurisdictionLocalityName',
        'businessCategory'
    ];
    const validsantypes = [
        'DNS',
        'IP',
        'URI',
        'email',
        'RID',
        'dirName',
        'otherName'
    ];
    var req = [];

    if(options.hasOwnProperty('module')) {
        if(options.module) {
            req.push('openssl_conf = openssl_def');
            req.push('[openssl_def]');
            req.push('engines = engine_section');
            req.push('[engine_section]');
            req.push('pkcs11 = pkcs11_section');
            req.push('[pkcs11_section]');
            req.push('engine_id = pkcs11');
            req.push('#dynamic_path = /usr/lib/x86_64-linux-gnu/engines-1.1/pkcs11.so');
            req.push('MODULE_PATH = ' + options.module);
            req.push('init = 0');
        }
    }
    
    if(cadir) {
        req.push('[ ca ]');
        req.push('default_ca = CA_default');
        req.push('[ CA_default ]');
        req.push('base_dir = ' + cadir);
        req.push('certificate = $base_dir/ca.crt');
        req.push('private_key = $base_dir/ca.key');
        req.push('new_certs_dir = $base_dir/certs ');
        req.push('database = $base_dir/index.txt');
        req.push('serial = $base_dir/serial.txt');
        req.push('unique_subject = no');
        req.push('default_days = 365');
        req.push('default_crl_days = 1');	
        req.push('default_md = ' + options.hash);
        req.push('preserve = yes');
        req.push('x509_extensions = req_ext');
        //req.push('email_in_dn = no');
        req.push('[ signing_policy ]');
        req.push('countryName = optional');
        req.push('stateOrProvinceName = optional');
        req.push('localityName = optional');
        req.push('postalCode = optional');
        req.push('streetAddress = optional');
        req.push('organizationName = optional');
        req.push('organizationalUnitName = optional');
        req.push('commonName = optional');
        req.push('emailAddress = optional');
        req.push('jurisdictionCountryName = optional');
        req.push('jurisdictionStateOrProvinceName = optional');
        req.push('jurisdictionLocalityName = optional');
        req.push('businessCategory = optional');
        req.push('serialNumber = optional');
        req.push('domainComponent = optional');
        req.push('surname = optional');
        req.push('title = optional');
        req.push('givenName = optional');
        req.push('UID = optional');
        req.push('initials = optional');
        req.push('generationQualifier = optional');
        req.push('dnQualifier = optional');
        req.push('pseudonym = optional');
    }
    
    req.push('[ req ]');
    req.push('default_md = ' + options.hash);
    req.push('prompt = no');
    if(options.string_mask) {
        req.push('string_mask = ' + options.string_mask);
    }
    if(options.requestAttributes) {
        req.push('attributes = req_attributes');
    }
    if(cert || options.extensions) {
        req.push('req_extensions = req_ext');
    }
    //if(options.subject) {
    req.push('distinguished_name = req_distinguished_name');
    req.push('[ req_distinguished_name ]');
    for (var prop in options.subject) {
        //console.log(prop + typeof(options.subject[prop]));
        if(validsubject.indexOf(prop) >=0 ) {
            //if(prop=='commonName' || prop=='organizationalUnitName') {
            if(typeof(options.subject[prop]) != 'string') {
                for(var i = 0; i <= options.subject[prop].length - 1; i++) {
                    req.push(i + '.' + prop + ' = ' + options.subject[prop][i]);
                }
            } else {
                req.push(prop + ' = ' + options.subject[prop]);
            }
        } else {
            callback('Invalid subject: ' + prop, false);
            return false;
        }
    }
    //}
    if(options.extensions) {
        if(options.extensions.policies) {
            let policyconfig = generatePolicyConfig(options.extensions.policies);
            for(let i = 0; i <= policyconfig.length - 1; i++) {
                req.push(policyconfig[i]);
            }
        }
    }
    /*req.push('userNotice.1=@notice1');
    req.push('userNotice.2=@notice2');
    req.push('[notice1]');
    req.push('explicitText="I can write anything I want here"');
    req.push('organization="Organisation Name"');
    req.push('noticeNumbers=1,2,3,4');
    req.push('[notice2]');
    req.push('explicitText="I can write anything I want here"');
    req.push('organization="Organisation Name"');
    req.push('noticeNumbers=1,2,3,4');*/

    if(options.requestAttributes) {
        req.push('[ req_attributes ]');
        
        for(var attr in options.requestAttributes) {
            //console.log(attr);
            if(options.requestAttributes[attr]) {
                if(validrequestattribute.indexOf(attr) < 0) {
                    callback('Invalid request attribute ' + attr, false);
                    return false;
                } else {
                    req.push(attr + '=' + options.requestAttributes[attr]);
                }
            }
        }
    }
    
    req.push('[ req_ext ]');
    /*if(options.mustStaple) {
        if(options.mustStaple==true) {
            req.push('1.3.6.1.5.5.7.1.24 = DER:30:03:02:01:05');
        }
    }*/
    if(cert) {
        //req.push('certificatePolicies = ia5org,2.5.29.32.0');
        req.push('subjectKeyIdentifier = hash');
        req.push('authorityKeyIdentifier = keyid:always,issuer');
    }
    if(options.extensions) {
        //req.push('[ req_ext ]');
        var endconfig = [];
        for(var ext in options.extensions) {
            if(ext == 'SANs') {
                if(options.extensions[ext]) {
                    if(Object.keys(options.extensions[ext]).length >= 1) {
                        var sansatend = [];
                        sansatend.push('subjectAltName = @alt_names');
                        sansatend.push('[ alt_names ]');
                        for(var type in options.extensions[ext]) {
                            if(validsantypes.indexOf(type) >= 0) {
                                for(var i = 0; i <= options.extensions[ext][type].length - 1; i++) {
                                    sansatend.push(type + '.' + i  + ' = ' + options.extensions[ext][type][i]);
                                }
                            } else {
                                callback('Invalid ' + ext + ' type : ' +  '"' + type + '"', false);
                                return false;
                            }
                        }
                    }
                }
            } else if (ext == 'customOIDs') {
                if(options.extensions[ext]) {
                    for(var i = 0; i <= options.extensions[ext].length - 1; i++) {
                        req.push(options.extensions[ext][i].OID + '=' + options.extensions[ext][i].value);
                    }
                }
            } else if (ext == 'extendedKeyUsage') {
                if(options.extensions[ext]) {
                    if(Object.keys(options.extensions[ext]).length >= 1) {
                        var critical = '';
                        var valid = 0;
                        for(var i = 0; i <= options.extensions[ext].usages.length - 1; i++) {
                            if(validextkeyusage.indexOf(options.extensions[ext].usages[i]) < 0 && /^([0-2])((\.0)|(\.[1-9][0-9]*))*$/.test(options.extensions[ext].usages[i]) === false) {
                                callback('Invalid ' + ext + ': ' + options.extensions[ext].usages[i], false);
                                return false;
                            } else {
                                valid++;
                            }
                        }
                        if(valid > 0) {
                            if(options.extensions[ext].critical) critical = 'critical,';
                            req.push(ext + '=' + critical + options.extensions[ext].usages.join(','));
                        }
                    }
                }
            } else if (ext == 'keyUsage') {
                if(options.extensions[ext]) {
                    if(Object.keys(options.extensions[ext]).length >= 1) {
                        var critical = '';
                        var valid = 0;
                        for(var i = 0; i <= options.extensions[ext].usages.length - 1; i++) {
                            //console.log(options.extensions[ext]);
                            if(validkeyusage.indexOf(options.extensions[ext].usages[i]) < 0) {
                                callback('Invalid ' + ext + ': ' + options.extensions[ext].usages[i], false);
                                return false;
                            } else {
                                valid++;
                            }
                        }
                        if(valid > 0) {
                            if(options.extensions[ext].critical) critical = 'critical,';
                            req.push(ext + '=' + critical + options.extensions[ext].usages.join(','));
                        }
                    }
                }
            } else if (ext == 'tlsfeature') {
                var critical = '';
                var valid = 0;
                for(var i = 0; i <= options.extensions[ext].length - 1; i++) {
                    //console.log(options.extensions[ext]);
                    if(validtlsfeature.indexOf(options.extensions[ext][i]) < 0) {
                        callback('Invalid ' + ext + ': ' + options.extensions[ext][i], false);
                        return false;
                    } else {
                        valid++;
                    }
                }
                if(valid > 0) {
                    //if(options.extensions[ext].critical) critical = 'critical,';
                    req.push(ext + '=' + options.extensions[ext].join(','));
                }
            } else if (ext == 'basicConstraints') {
                if(options.extensions[ext]) {
                    if(Object.keys(options.extensions[ext]).length >= 1) {
                        var bccmd = [];
                        var valid = 0;
                        for(var type in options.extensions[ext]) {
                            if(type=='critical') {
                                var reqtype = 'boolean';
                                if(typeof(options.extensions[ext][type]) == reqtype) {
                                    if (options.extensions[ext][type]) {
                                        bccmd.unshift('critical');
                                    } else {
                                        //not critical
                                    }
                                    valid++;
                                } else {
                                    callback('Provided ' + ext + ' parameter \'' + type + '\' is type ' + typeof(options.extensions[ext][type]) + ', ' + reqtype + ' required', false);
                                    return false;
                                }
                                //console.log(options.extensions[ext][type]);
                            } else if(type=='CA') {
                                var reqtype = 'boolean';
                                if(typeof(options.extensions[ext][type]) == reqtype) {
                                    if (options.extensions[ext][type]) {
                                        bccmd.push('CA:true');
                                    } else {
                                        bccmd.push('CA:false');
                                    }
                                    valid++;
                                } else {
                                    callback('Provided ' + ext + ' parameter \'' + type + '\' is type ' + typeof(options.extensions[ext][type]) + ', ' + reqtype + ' required', false);
                                    return false;
                                }
                            } else if(type=='pathlen') {
                                var reqtype = 'number';
                                if(typeof(options.extensions[ext][type]) == reqtype) {
                                    if (options.extensions[ext][type] >= 0) {
                                        bccmd.push('pathlen:' + options.extensions[ext][type]);
                                    } else {
                                        //optional pathlen not defined
                                    }
                                    valid++;
                                } else {
                                    callback('Provided ' + ext + ' parameter \'' + type + '\' is type ' + typeof(options.extensions[ext][type]) + ', ' + reqtype + ' required', false);
                                    return false;
                                }
                            } else {
                                callback('Invalid ' + ext + ': ' + type, false);
                                return false;
                            }
                        }
                        if(valid > 0) {
                            req.push('basicConstraints=' + bccmd.join(','));
                        }
                        if(valid == 1 && bccmd[0]=='critical') {
                            callback('Basic constraints cannot contain only \'critical\'', false);
                            return false;
                        }
                    }
                }
            } else if (ext == 'authorityInfoAccess') {
                let aiaconfig = [];
                if(options.extensions[ext]['OCSP']) {
                    for(var i = 0; i <= options.extensions[ext]['OCSP'].length - 1; i++) {
                        aiaconfig.push('OCSP;URI.' + i + ' = ' + options.extensions[ext]['OCSP'][i]);
                    }
                }
                if(options.extensions[ext]['caIssuers']) {
                    for(var i = 0; i <= options.extensions[ext]['caIssuers'].length - 1; i++) {
                        aiaconfig.push('caIssuers;URI.' + i + ' = ' + options.extensions[ext]['caIssuers'][i]);
                    }
                }
                if(aiaconfig.length > 0) {
                    req.push('authorityInfoAccess = @issuer_info');
                    endconfig.push('[ issuer_info ]');
                    for(var i = 0; i <= aiaconfig.length - 1; i++) {
                        endconfig.push(aiaconfig[i]);
                    }
                }
            } else if (ext == 'crlDistributionPoints') {
                if(options.extensions[ext].length > 0) {
                    req.push('crlDistributionPoints = @crl_info');
                    endconfig.push('[ crl_info ]');
                    for(var i = 0; i <= options.extensions[ext].length - 1; i++) {
                        endconfig.push('URI.' + i + ' = ' + options.extensions[ext][i]);
                    }
                }
            } else if (ext == 'policies') {
                if(options.extensions[ext].length > 0) {
                    let policyIndexes = []
                    //req.push('crlDistributionPoints = @crl_info');
                    //endconfig.push('[ crl_info ]');
                    for(var i = 0; i <= options.extensions[ext].length - 1; i++) {
                        //endconfig.push('URI.' + i + ' = ' + options.extensions[ext][i]);
                        if(options.extensions[ext][i]['policyIdentifier']) {
                            policyIndexes.push('@polsect' + i);
                        }
                    }
                    if(policyIndexes.length >= 1) {
                        req.push('certificatePolicies = ia5org,' + policyIndexes.join(','));
                    }
                }
            } else {
                callback('Invalid extension: ' + ext, false);
                return false;
            }
        }
        if(sansatend) {
            for(var i = 0; i <= sansatend.length - 1; i++) {
                req.push(sansatend[i]);
            }
        }
        if(endconfig.length > 0) {
            for(var i = 0; i <= endconfig.length - 1; i++) {
                req.push(endconfig[i]);
            }
        }
    }
    callback(false, req);
    //console.log(req);
}

module.exports = generate;