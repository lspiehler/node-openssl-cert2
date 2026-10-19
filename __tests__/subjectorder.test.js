const node_openssl = require('../index.js');
const { execFile } = require('child_process');
var openssl = new node_openssl();

function call(fn, params) {
    return new Promise(function(resolve) {
        fn(params, function(err, result) {
            resolve({err: err, result: result});
        });
    });
}

// CSRs are made by OpenSSL directly, as clients make them, so the subject keeps the order of -subj
function opensslReq(dn) {
    const tmp = require('tmp');
    const fs = require('fs');
    const dir = tmp.dirSync({unsafeCleanup: true});
    fs.writeFileSync(dir.name + '/key.pem', key);
    fs.writeFileSync(dir.name + '/req.cnf', '[ req ]\ndistinguished_name = dn\nstring_mask = utf8only\n[ dn ]\n');
    return new Promise(function(resolve, reject) {
        execFile('openssl', ['req', '-new', '-key', dir.name + '/key.pem', '-config', dir.name + '/req.cnf', '-utf8', '-subj', dn], function(err, stdout) {
            dir.removeCallback();
            if(err) {
                reject(err);
            } else {
                resolve(stdout);
            }
        });
    });
}

let key;
let ca;

beforeAll(async () => {
    key = (await call(openssl.keypair.generateECC, {curve: 'prime256v1'})).result.data;
    const cacsr = await call(openssl.csr.create, {options: {subject: {commonName: 'Subject Order Test CA'}}, key: key});
    ca = (await call(openssl.x509.selfSignCSR, {
        options: {days: 1, subject: {commonName: 'Subject Order Test CA'}, extensions: {basicConstraints: {critical: true, CA: true}}},
        csr: cacsr.result.data,
        key: key
    })).result.data;
});

// signs the CSR and returns the issued subject as [type=value] in encoded order
async function sign(csr, options) {
    const signed = await call(openssl.x509.CASignCSR, {csr: csr, ca: ca, key: key, options: Object.assign({days: 1}, options)});
    expect(signed.err).toEqual(false);
    const cert = await call(openssl.x509.parse, {cert: signed.result.data});
    expect(cert.err).toEqual(false);
    return cert.result.data.subjectList.map(function(attribute) { return attribute.type + '=' + attribute.value; });
}

const policyOrder = [
    ['/CN=user/DC=com/DC=example', ['domainComponent=com', 'domainComponent=example', 'commonName=user']],
    ['/CN=Jane Doe/emailAddress=jane@example.com/SN=Doe/GN=Jane', ['surname=Doe', 'givenName=Jane', 'commonName=Jane Doe', 'emailAddress=jane@example.com']],
    ['/CN=host/C=US/L=City/ST=State/O=Org/OU=Unit', ['countryName=US', 'stateOrProvinceName=State', 'localityName=City', 'organizationName=Org', 'organizationalUnitName=Unit', 'commonName=host']],
    ['/OU=a/O=b/OU=c/CN=x', ['organizationName=b', 'organizationalUnitName=a', 'organizationalUnitName=c', 'commonName=x']],
    ['/unstructuredAddress=192.0.2.1/unstructuredName=router.example.com/organizationIdentifier=VATDE-123456789/CN=x/O=Org', ['organizationName=Org', 'commonName=x', 'organizationIdentifier=VATDE-123456789', 'unstructuredName=router.example.com', 'unstructuredAddress=192.0.2.1']]
];

test.each(policyOrder)('%s is issued in the Baseline Requirements order by default', async (dn, expected) => {
    const csr = await opensslReq(dn);
    const parsed = await call(openssl.csr.parse, {csr: csr});
    expect(await sign(csr, {subject: parsed.result.data.subject})).toEqual(expected);
    expect(await sign(csr, {subject: parsed.result.data.subjectList})).toEqual(expected);
    expect(await sign(csr, {})).toEqual(expected);
});

const csrOrder = ['/CN=user/DC=com/DC=example', '/OU=a/O=b/OU=c/CN=x', '/CN=Ops\\/Infra a\\+b back\\\\slash/O=Smith, Jones/C=US', '/emailAddress=jane@example.com/GN=Jane/SN=Doe/CN=Jane Doe'];

test.each(csrOrder)('%s keeps the CSR order with preserveDN', async (dn) => {
    const csr = await opensslReq(dn);
    const parsed = await call(openssl.csr.parse, {csr: csr});
    const expected = parsed.result.data.subjectList.map(function(attribute) { return attribute.type + '=' + attribute.value; });
    expect(await sign(csr, {subject: parsed.result.data.subjectList, preserveDN: true})).toEqual(expected);
    expect(await sign(csr, {preserveDN: true})).toEqual(expected);
});

test('preserveDN with a subject object keeps the order of its keys', async () => {
    const csr = await opensslReq('/CN=x');
    expect(await sign(csr, {subject: {commonName: 'x', organizationalUnitName: ['a', 'b'], countryName: 'US'}, preserveDN: true})).toEqual(['commonName=x', 'organizationalUnitName=a', 'organizationalUnitName=b', 'countryName=US']);
});

test('The subject list is in encoded order and matches the subject object', async () => {
    const csr = await opensslReq('/CN=x/O=Smith, Jones/OU=a/OU=b');
    const parsed = await call(openssl.csr.parse, {csr: csr});
    expect(parsed.result.data.subjectList).toEqual([
        {type: 'commonName', value: 'x'},
        {type: 'organizationName', value: 'Smith, Jones'},
        {type: 'organizationalUnitName', value: 'a'},
        {type: 'organizationalUnitName', value: 'b'}
    ]);
    expect(parsed.result.data.subject).toEqual({commonName: 'x', organizationName: 'Smith, Jones', organizationalUnitName: ['a', 'b']});
});

test('A subject list with an unknown attribute type is refused', async () => {
    const csr = await opensslReq('/CN=x');
    const signed = await call(openssl.x509.CASignCSR, {csr: csr, ca: ca, key: key, options: {days: 1, subject: [{type: 'commonName', value: 'x'}, {type: 'name', value: 'n'}]}});
    expect(signed.err).toEqual('Invalid subject: name');
    expect(openssl.x509.getDistinguishedName([{type: 'commonName'}])).toEqual(false);
    expect(openssl.x509.getDistinguishedName([])).toEqual('/');
});

test('An empty subject list is null and unknown names are kept as printed', () => {
    expect(openssl.x509.getSubjectList('        Subject: \n')).toEqual(null);
    expect(openssl.x509.getSubjectList('        Subject: name=n, CN=c\n')).toEqual([{type: 'name', value: 'n'}, {type: 'commonName', value: 'c'}]);
});

test('csr.create writes a subject list in its order', async () => {
    const list = [{type: 'domainComponent', value: 'com'}, {type: 'domainComponent', value: 'example'}, {type: 'organizationalUnitName', value: 'a'}, {type: 'commonName', value: 'Smith, Jones'}, {type: 'organizationalUnitName', value: 'b'}];
    const csr = await call(openssl.csr.create, {options: {subject: list}, key: key});
    expect(csr.err).toEqual(false);
    const parsed = await call(openssl.csr.parse, {csr: csr.result.data});
    expect(parsed.result.data.subjectList).toEqual(list);
});
