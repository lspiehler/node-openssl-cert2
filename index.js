'use strict';
const fs = require('fs');
const keypair = require("./lib/keypair");
const binary = require("./lib/binary");
const crypto = require("./lib/crypto");
const csr = require("./lib/csr");
const x509 = require("./lib/x509");
const crl = require("./lib/crl");
const pkcs11 = require("./lib/pkcs11");
const softhsm2 = require("./lib/softhsm2");
const smime = require("./lib/smime");

var openssl = function(options) {

    if(options) {
		if(options.binpath) {
			binary.openssl.setPath(options.binpath);
		}
		if(options.debug) {
			binary.openssl.enableDebug();
		}
		if(options.pkcs11toolbinpath) {
			binary.pkcs11Tool.setPath(options.pkcs11toolbinpath);
		}
		if(options.libdir) {
			binary.pkcs11Tool.setLibDir(options.libdir);
		}
	}

	this.keypair = keypair;
    this.binary = binary;
    this.crypto = crypto;
    this.csr = csr;
    this.x509 = x509;
    this.crl = crl;
	this.pkcs11 = pkcs11;
	this.softhsm2 = softhsm2;
	this.smime = smime;
}

module.exports = openssl;