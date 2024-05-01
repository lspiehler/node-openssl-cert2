'use strict';
const fs = require('fs');
const keypair = require("./lib/keypair");
const binary = require("./lib/binary");
const crypto = require("./lib/crypto");
const csr = require("./lib/csr");
const x509 = require("./lib/x509");

var openssl = function(options) {

    if(options) {
		if(options.binpath) {
			binary.setPath(options.binpath);
		}
		if(options.debug) {
			binary.enableDebug();
		}
	}

	this.keypair = keypair;
    this.binary = binary;
    this.crypto = crypto;
    this.csr = csr;
    this.x509 = x509;
}

module.exports = openssl;