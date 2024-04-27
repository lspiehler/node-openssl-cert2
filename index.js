'use strict';
const fs = require('fs');
const keypair = require("./lib/keypair");
const binary = require("./lib/binary");
const crypto = require("./lib/crypto");

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
}

module.exports = openssl;