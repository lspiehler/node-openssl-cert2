const node_openssl = require('../index.js');
const { execFile } = require('child_process');
var openssl = new node_openssl();

// characters that OpenSSL prints without escaping (-nameopt utf8) and that used to be split on or removed
const values = [
    'plain', 'Smith, Jones', 'Ops/Infra', 'a=b', 'a+b', 'quoted "x"', "O'Brien", 'back\\slash', 'trail\\', ' lead', 'trail ',
    'x, CN=evil', '#hash', 'semi;colon', '<angle>', 'colon: x', 'two  spaces', 'Subject: CN=z', 'Ünïcødé', '日本語', 'emoji 🔒'
];

const printable = function(value) {
    return /^[A-Za-z0-9 '()+,\-./:=?]*$/.test(value);
}
const ascii = function(value) {
    return /^[\x20-\x7e]*$/.test(value);
}

// OpenSSL encodes some attributes as PrintableString or IA5String whatever the string mask is
const attributes = {
    countryName: ['US'],
    stateOrProvinceName: values,
    localityName: values,
    postalCode: values,
    streetAddress: values,
    organizationName: values,
    organizationalUnitName: values,
    commonName: values,
    emailAddress: values.filter(ascii),
    jurisdictionLocalityName: values,
    jurisdictionStateOrProvinceName: values,
    jurisdictionCountryName: ['US'],
    serialNumber: values.filter(printable),
    businessCategory: values,
    domainComponent: values.filter(ascii),
    surname: values,
    title: values,
    givenName: values,
    UID: values,
    initials: values,
    generationQualifier: values,
    dnQualifier: values.filter(printable),
    pseudonym: values
}

// UTF8String, PrintableString/T61String (Latin-1 only) and BMPString (as Windows writes them; no characters outside the BMP)
const masks = {
    'utf8only': function(value) { return true; },
    'nombstr': function(value) { return /^[\x00-\xff]*$/.test(value); },
    'MASK:0x800': function(value) { return !/[\u{10000}-\u{10ffff}]/u.test(value); }
}

function call(fn, params) {
    return new Promise(function(resolve) {
        fn(params, function(err, result) {
            resolve({err: err, result: result});
        });
    });
}

// CSRs are made by OpenSSL directly, as clients make them, with the string mask in a config file
function opensslReq(args, mask) {
    const tmp = require('tmp');
    const fs = require('fs');
    const dir = tmp.dirSync({unsafeCleanup: true});
    fs.writeFileSync(dir.name + '/key.pem', key);
    fs.writeFileSync(dir.name + '/req.cnf', '[ req ]\ndistinguished_name = dn\nstring_mask = ' + (mask || 'utf8only') + '\n[ dn ]\n');
    return new Promise(function(resolve, reject) {
        execFile('openssl', ['req', '-new', '-key', dir.name + '/key.pem', '-config', dir.name + '/req.cnf', '-utf8'].concat(args), function(err, stdout) {
            dir.removeCallback();
            if(err) {
                reject(err);
            } else {
                resolve(stdout);
            }
        });
    });
}

// -subj escapes
const subj = function(value) {
    return value.replace(/[\\/+]/g, '\\$&');
}

let key;
let ca;

beforeAll(async () => {
    key = (await call(openssl.keypair.generateECC, {curve: 'prime256v1'})).result.data;
    const cacsr = await call(openssl.csr.create, {options: {subject: {commonName: 'Subject Parsing Test CA'}}, key: key});
    ca = (await call(openssl.x509.selfSignCSR, {
        options: {days: 1, subject: {commonName: 'Subject Parsing Test CA'}, extensions: {basicConstraints: {critical: true, CA: true}}},
        csr: cacsr.result.data,
        key: key
    })).result.data;
});

const cases = [];
for(let mask in masks) {
    for(let attribute in attributes) {
        cases.push([mask, attribute]);
    }
}

test.each(cases)('%s %s values are parsed from the CSR and issued as they are', async (mask, attribute) => {
    const expected = attributes[attribute].filter(masks[mask]);
    const names = {};
    names[attribute] = expected;
    let dn = expected.map(function(value) { return '/' + attribute + '=' + subj(value); }).join('');
    if(attribute != 'commonName') {
        names.commonName = 'fixed';
        dn += '/commonName=fixed';
    }
    const csr = await opensslReq(['-subj', dn], mask);
    const parsed = await call(openssl.csr.parse, {csr: csr});
    expect(parsed.err).toEqual(false);
    expect(parsed.result.data.subject[attribute]).toEqual(expected.length == 1 ? expected[0] : expected);
    if(attribute != 'commonName') {
        expect(parsed.result.data.subject.commonName).toEqual('fixed');
    }
    expect(Object.keys(parsed.result.data.subject).length).toEqual(Object.keys(names).length);
    const signed = await call(openssl.x509.CASignCSR, {csr: csr, ca: ca, key: key, options: {days: 1, subject: parsed.result.data.subject}});
    expect(signed.err).toEqual(false);
    const cert = await call(openssl.x509.parse, {cert: signed.result.data});
    expect(cert.err).toEqual(false);
    expect(cert.result.data.subject).toEqual(parsed.result.data.subject);
}, 30000);

test('Issuer and Subject String are printed as before, without the escapes used for parsing', async () => {
    const subject = {organizationName: 'Smith, Jones', commonName: 'quoted "x" a+b back\\slash'};
    const csr = await call(openssl.csr.create, {options: {subject: subject}, key: key});
    const parsed = await call(openssl.csr.parse, {csr: csr.result.data});
    expect(parsed.result.data.attributes['Subject String']).toEqual('O=Smith, Jones, CN=quoted "x" a+b back\\slash');
    const signed = await call(openssl.x509.selfSignCSR, {options: {days: 1, subject: subject}, csr: csr.result.data, key: key});
    const cert = await call(openssl.x509.parse, {cert: signed.result.data});
    expect(cert.result.data.attributes['Subject String']).toEqual('O=Smith, Jones, CN=quoted "x" a+b back\\slash');
    expect(cert.result.data.attributes['Issuer']).toEqual('O=Smith, Jones, CN=quoted "x" a+b back\\slash');
});

test('Members of a multi-valued RDN become separate attributes', async () => {
    const csr = await opensslReq(['-subj', '/O=org/OU=Ops+CN=x', '-multivalue-rdn']);
    const parsed = await call(openssl.csr.parse, {csr: csr});
    expect(parsed.result.data.subject).toEqual({organizationName: 'org', commonName: 'x', organizationalUnitName: 'Ops'});
});

test('An empty subject is null', async () => {
    const csr = await opensslReq(['-subj', '/']);
    const parsed = await call(openssl.csr.parse, {csr: csr});
    expect(parsed.result.data.subject).toEqual(null);
});

test('Only the Subject line of the certificate itself is parsed', () => {
    const text = [
        'Certificate Request:',
        '    Data:',
        '        Subject: CN=real\\, name',
        '        Requested Extensions:',
        '            X509v3 Subject Alternative Name:',
        '                DNS:Subject: CN=evil'
    ].join('\n');
    expect(openssl.x509.getSubject(text)).toEqual({commonName: 'real, name'});
});

test('Attributes without a known name keep the name OpenSSL prints', () => {
    expect(openssl.x509.getSubject('        Subject: organizationIdentifier=VATDE-1, 1.2.3.4=x, CN=c\n')).toEqual({organizationIdentifier: 'VATDE-1', '1.2.3.4': 'x', commonName: 'c'});
});
