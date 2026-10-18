const node_openssl = require('../index.js');
const { execFile } = require('child_process');
var openssl = new node_openssl();

// values go into an openssl.cnf, where OpenSSL would expand $ENV::NAME, cut a value at # and drop quotes
process.env.CONFIGVALUESTEST = 'EXPANDED';
const literal = 'a$ENV::CONFIGVALUESTEST ${ENV::CONFIGVALUESTEST} #"\'\\b';

function opensslText(command, pem) {
    return new Promise(function(resolve, reject) {
        const child = execFile('openssl', [command, '-noout', '-text', '-nameopt', 'utf8,sep_comma_plus'], function(err, stdout) {
            if(err) {
                reject(err);
            } else {
                resolve(stdout);
            }
        });
        child.stdin.end(pem);
    });
}

function call(fn, params) {
    return new Promise(function(resolve) {
        fn(params, function(err, result) {
            resolve({err: err, result: result});
        });
    });
}

async function signedWith(options) {
    const key = await call(openssl.keypair.generateECC, {curve: 'prime256v1'});
    const ca = await call(openssl.x509.selfSignCSR, {
        options: {days: 1, subject: {commonName: 'Config Values Test CA'}, extensions: {basicConstraints: {critical: true, CA: true}}},
        csr: (await call(openssl.csr.create, {options: {subject: {commonName: 'Config Values Test CA'}}, key: key.result.data})).result.data,
        key: key.result.data
    });
    const csr = await call(openssl.csr.create, {options: {subject: {commonName: 'leaf'}}, key: key.result.data});
    return call(openssl.x509.CASignCSR, {csr: csr.result.data, ca: ca.result.data, key: key.result.data, options: options});
}

test('Values with $, #, quotes and backslashes reach the certificate as they are', async () => {
    const signed = await signedWith({
        days: 1,
        subject: {commonName: literal},
        extensions: {
            SANs: {DNS: [literal], URI: ['http://example.com/$ENV::CONFIGVALUESTEST#x'], otherName: ['msUPN;UTF8:' + literal]},
            crlDistributionPoints: ['http://crl.example.com/$ENV::CONFIGVALUESTEST#x'],
            authorityInfoAccess: {OCSP: ['http://ocsp.example.com/$ENV::CONFIGVALUESTEST'], caIssuers: ['http://ca.example.com/#x']},
            policies: [{policyIdentifier: '1.2.3.4', CPS: ['https://cps.example.com/' + literal]}]
        }
    });
    expect(signed.err).toEqual(false);
    const text = await opensslText('x509', signed.result.data);
    expect(text).not.toContain('EXPANDED');
    expect(text).toContain('DNS:' + literal);
    expect(text).toContain('othername: UPN:' + literal);
    expect(text).toContain('URI:http://example.com/$ENV::CONFIGVALUESTEST#x');
    expect(text).toContain('URI:http://crl.example.com/$ENV::CONFIGVALUESTEST#x');
    expect(text).toContain('OCSP - URI:http://ocsp.example.com/$ENV::CONFIGVALUESTEST');
    expect(text).toContain('CA Issuers - URI:http://ca.example.com/#x');
    expect(text).toContain('CPS: https://cps.example.com/' + literal);
});

test('A CSR subject and request attribute keep $, #, quotes and backslashes as they are', async () => {
    const key = await call(openssl.keypair.generateECC, {curve: 'prime256v1'});
    const csr = await call(openssl.csr.create, {
        options: {subject: {commonName: literal, organizationalUnitName: ['$ENV::CONFIGVALUESTEST']}, requestAttributes: {challengePassword: 'pa$$#word'}},
        key: key.result.data
    });
    expect(csr.err).toEqual(false);
    const text = await opensslText('req', csr.result.data);
    expect(text).not.toContain('EXPANDED');
    expect(text).toContain('Subject: CN=' + literal + ',OU=$ENV::CONFIGVALUESTEST');
    expect(text).toContain('challengePassword        :pa$$#word');
});

test('Control characters, which would start new config lines, are rejected', async () => {
    const key = await call(openssl.keypair.generateECC, {curve: 'prime256v1'});
    const subject = await call(openssl.csr.create, {options: {subject: {commonName: 'a\r\n[ req_ext ]\r\nbasicConstraints = CA:true'}}, key: key.result.data});
    expect(subject.err).toEqual('Invalid control character in options.subject.commonName');
    const san = await signedWith({days: 1, extensions: {SANs: {DNS: ['a\nb']}}});
    expect(san.err).toEqual('Invalid control character in options.extensions.SANs.DNS.0');
});

test('A hash that is not a plain name is rejected', async () => {
    const signed = await signedWith({days: 1, hash: 'sha256$ENV::CONFIGVALUESTEST'});
    expect(signed.err).toEqual('Invalid hash: sha256$ENV::CONFIGVALUESTEST');
});
