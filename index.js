'use strict';
const fs = require('fs');
const keypair = require("./lib/keypair");
const binary = require("./lib/binary");
const crypto = require("./lib/crypto");
const csr = require("./lib/csr");
const x509 = require("./lib/x509");
const crl = require("./lib/crl");

var openssl = function(options) {

    if(options) {
		if(options.binpath) {
			binary.openssl.setPath(options.binpath);
		}
		if(options.debug) {
			binary.openssl.enableDebug();
		}
	}

	this.keypair = keypair;
    this.binary = binary;
    this.crypto = crypto;
    this.csr = csr;
    this.x509 = x509;
    this.crl = crl;
}

module.exports = openssl;