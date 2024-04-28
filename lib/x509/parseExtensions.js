const nameMappings = require('./nameMappings');
const binary = require('../binary');

const getCDP = function(cdp, callback) {
    //console.log(cdp);
    let cdpitems = [];
    for(let i = 0; i <= cdp.content.length - 1; i++) {
        if(cdp.content[i].indexOf('URI:') >= 0) {
            cdpitems.push(cdp.content[i].replace('URI:', ''));
        }
    }
    if(cdpitems.length > 0) {
        callback(false, cdpitems);
    } else {
        callback(false, false);
    }
}

const getAIA = function(aia, callback) {
    //console.log(aia.content);
    var ocspitems = [];
    var aiaitems = [];
    //var valid = ['OCSP', 'CA Issuers']
    for(let i = 0; i <= aia.content.length - 1; i++) {
        //if(aia.content[i].split('-')[0].trim().indexOf()) {
        let attritem = aia.content[i].split(' - ')
        //console.log(valid.indexOf(attritem[0].trim()));
        if(attritem[0].trim() == 'OCSP') {
            ocspitems.push(attritem[1].trim().replace('URI:', ''));
        } else if(attritem[0].trim() == 'CA Issuers') {
            aiaitems.push(attritem[1].trim().replace('URI:', ''));
        } else {
            
        }
    }
    let authorityInfoAccess = false;
    if(ocspitems.length > 0 || aiaitems.length > 0) {
        authorityInfoAccess = {}
        if(ocspitems.length > 0) {
            authorityInfoAccess.OCSP = ocspitems;
        }
        if(aiaitems.length > 0) {
            authorityInfoAccess.caIssuers = aiaitems;
        }
        callback(false, authorityInfoAccess);
    } else {
        callback(false, false);
    }
}

const getTLSFeature = function(feature, callback) {
    var tlsfeature = []
    var index = {
        'status_request': 'status_request',
    }
    var tlsfeatures = feature.content[0].split(', ');
    for(var i = 0; i <= tlsfeatures.length - 1; i++) {
        tlsfeature.push(index[tlsfeatures[i]]);
    }
    callback(null, tlsfeature);
}

const getExtendedKeyUsage = function(eku, callback) {
    var extendedkeyusage = {}
    /*var index = {
        'TLS Web Server Authentication': 'serverAuth',
        'TLS Web Client Authentication': 'clientAuth',
        'Code Signing': 'codeSigning',
        'E-mail Protection': 'emailProtection',
        'Time Stamping': 'timeStamping',
        'OCSP Signing': 'OCSPSigning',
        'Microsoft Individual Code Signing': 'msCodeInd',
        'Microsoft Commercial Code Signing': 'msCodeCom',
        'Microsoft Trust List Signing': 'msCTLSign',
        'Microsoft Encrypted File System': 'msEFS',
        'ipsec Internet Key Exchange': 'ipsecIKE',
        'IPSec End System': 'ipsecEndSystem',
        'IPSec Tunnel': 'ipsecTunnel',
        'IPSec User': 'ipsecUser',
        '1.3.6.1.4.1.311.20.2.1': '1.3.6.1.4.1.311.20.2.1'
    }*/
    let oids = nameMappings;
    var extendedkeyusages = eku.content[0].split(', ');
    if(eku.critical) extendedkeyusage.critical = true;
    extendedkeyusage['usages'] = [];
    for(var i = 0; i <= extendedkeyusages.length - 1; i++) {
        if(oids.hasOwnProperty(extendedkeyusages[i])) {
            extendedkeyusage['usages'].push(oids[extendedkeyusages[i]]);
        } else {
            extendedkeyusage['usages'].push(extendedkeyusages[i]);
        }
    }
    callback(null, extendedkeyusage);
}

const getBasicConstraints = function(bc, callback) {
    //console.log(bc);
    var basicConstraints = {};
    var constraints = bc.content[0].split(', ');
    if(bc.critical) basicConstraints.critical = true;
    for(var i = 0; i <= constraints.length - 1; i++) {
        var value;
        var constraint = constraints[i].split(':');
        if(constraint[1]=='TRUE') {
            value = true;
        } else if(constraint[1]=='FALSE') {
            value = false
        } else if(!isNaN(constraint[1])) {
            value = parseInt(constraint[1]);
        } else {
            value = constraint[1]
        }
        basicConstraints[constraint[0]] = value;
    }
    callback(null, basicConstraints);
}

const getKeyUsage = function(ku, callback) {
    var keyusage = {}
    var index = {
        'Digital Signature': 'digitalSignature',
        'Key Encipherment': 'keyEncipherment',
        'Non Repudiation': 'nonRepudiation',
        'Data Encipherment': 'dataEncipherment',
        'Key Agreement': 'keyAgreement',
        'Certificate Sign': 'keyCertSign',
        'CRL Sign': 'cRLSign',
        'Encipher Only': 'encipherOnly',
        'Decipher Only': 'decipherOnly'
    }
    var keyusages = ku.content[0].split(', ');
    if(ku.critical) keyusage.critical = true;
    keyusage['usages'] = [];
    for(var i = 0; i <= keyusages.length - 1; i++) {
        keyusage['usages'].push(index[keyusages[i]]);
    }
    callback(false, keyusage);
}

const getSubjectAlternativeNames = function(sans, originalcert, callback) {
    var names = {}
    let processedunsupportedtypes = false;
    if(sans.content[0]) {
        var sanarr = sans.content[0].split(', ');
        for(var i = 0; i <= sanarr.length - 1; i++) {
            var san = sanarr[i].split(':');
            var type;
            if(san[0]=='IP Address') {
                type = 'IP';
            } else if(san[0]=='Registered ID') {
                type = 'RID';
            } else {
                type = san[0];
            }
            san.shift();
            var value = san.join(':');
            //console.log(type + ' - ' + value);
            if(value!='<unsupported>') {
                if(names[type]) {
                    names[type].push(value);
                } else {
                    names[type] = [value];
                }
            } else {
                if(!processedunsupportedtypes) {
                    processedunsupportedtypes = true;
                }
            }
        }
        
        if(processedunsupportedtypes) {
            getUnsupportedSANs(originalcert, function(err, otherNames) {
                if(err) {
                    return false;
                } else {
                    names['otherName'] = otherNames;
                    /*if(Object.keys(names).length > 0) {
                        return names;
                    } else {
                        return false;
                    }*/
                    //console.log(names);
                    callback(null, names);
                }
            });
        } else {
            /*if(Object.keys(names).length > 0) {
                return names;
            } else {
                return false;
            }*/
            //console.log(names);
            callback(null, names);
        }
    } else {
        callback(null, {});
    }
}

var getUnsupportedSANs = function(cert, callback) {
    console.log('WE ARE HERE');
    let oids = name_mappings;
    let otherNameSANs = [];
    tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
        if (err) throw err;
        fs.writeFile(path, cert, function() {
            let cmd = ['asn1parse -in ' + path + ' -inform pem'];
            binary.runOpenSSLCommand({cmd: cmd.join(' ')}, function(err, out) {
                //cleanupCallback1();
                if(err) {
                    //console.log(err);
                    cleanupCallback1();
                    callback(err, false);
                } else {
                    let lines = out.stdout.split('\n');
                    for(let i = 1; i <= lines.length - 1; i++) {
                        if(lines[i].indexOf('X509v3 Subject Alternative Name') >= 1) {
                            let start = lines[i + 1].split(':')[0].trim();
                            cmd.push('-strparse ' + start);
                            binary.runOpenSSLCommand({cmd: cmd.join(' ')}, function(err, out) {
                                if(err) {
                                    //console.log(err);
                                    cleanupCallback1();
                                    callback(err, false);
                                } else {
                                    //console.log(out.stdout);
                                    let lines = out.stdout.split('\n');
                                    for(let j = 1; j <= lines.length - 1; j++) {
                                        if(lines[j].indexOf('cont [ 0 ]') >= 1) {
                                            if(lines[j + 1].indexOf('OBJECT') >= 1) {
                                                if(lines[j + 3].indexOf('UTF8STRING') >= 1) {
                                                    let oid = lines[j + 1].split(':')[3].replace('\r','');
                                                    //console.log(oid);
                                                    if(oids.hasOwnProperty(oid)) {
                                                        otherNameSANs.push(oids[oid] + ';UTF8:' + lines[j + 3].split(':')[3].replace('\r',''));
                                                    } else {
                                                        otherNameSANs.push(oid + ';UTF8:' + lines[j + 3].split(':')[3].replace('\r',''));
                                                    }
                                                    //console.log(otherNameSANs);
                                                    //console.log(lines[j + 3].split(':')[3].replace('\r',''));
                                                    j = j + 1;
                                                }
                                            }
                                        }
                                    }
                                }
                                callback(null, otherNameSANs);
                            });
                            break;
                        }
                    }
                }
            });
        });
    });
}

const parseExtensions = function(originalcert, parsedextensions, extensions, index, callback) {
    if(!extensions) {
        var extensions = {}
    }
    let ext = Object.keys(parsedextensions);
    if(ext.length > index) {
        //console.log(ext[index]);
        if(ext[index]=='Subject Alternative Name') {
            getSubjectAlternativeNames(parsedextensions[ext[index]], originalcert, function(err, attrs) {
                extensions['SANs'] = attrs;
                parseExtensions(originalcert, parsedextensions, extensions, index + 1, callback);
            });
        } else if(ext[index]=='Key Usage') {
            getKeyUsage(parsedextensions[ext[index]], function(err, attrs) {
                extensions['keyUsage'] = attrs;
                parseExtensions(originalcert, parsedextensions, extensions, index + 1, callback);
            });
        } else if(ext[index]=='Extended Key Usage') {
            getExtendedKeyUsage(parsedextensions[ext[index]], function(err, attrs) {
                extensions['extendedKeyUsage'] = attrs;
                parseExtensions(originalcert, parsedextensions, extensions, index + 1, callback);
            });
        } else if(ext[index]=='Basic Constraints') {
            getBasicConstraints(parsedextensions[ext[index]], function(err, attrs) {
                extensions['basicConstraints'] = attrs;
                parseExtensions(originalcert, parsedextensions, extensions, index + 1, callback);
            });
        } else if(ext[index]=='TLS Feature') {
            getTLSFeature(parsedextensions[ext[index]], function(err, attrs) {
                extensions['tlsfeature'] = attrs;
                parseExtensions(originalcert, parsedextensions, extensions, index + 1, callback);
            });
        } else if(ext[index]=='Authority Information Access') {
            getAIA(parsedextensions[ext[index]], function(err, attrs) {
                extensions['authorityInfoAccess'] = attrs;
                parseExtensions(originalcert, parsedextensions, extensions, index + 1, callback);
            });
        } else if(ext[index]=='CRL Distribution Points') {
            getCDP(parsedextensions[ext[index]], function(err, attrs) {
                extensions['crlDistributionPoints'] = attrs;
                parseExtensions(originalcert, parsedextensions, extensions, index + 1, callback);
            });
        } else {
            parseExtensions(originalcert, parsedextensions, extensions, index + 1, callback);
        }
    } else {
        //console.log(extensions);
        callback(null, extensions);
    }
}

module.exports = parseExtensions;