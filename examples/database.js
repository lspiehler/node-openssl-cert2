const node_openssl = require('../index.js');
const key = require('../lib/crypto/key.js');
var openssl = new node_openssl({binpath: '/opt/openssl32/bin/openssl', debug: false});
var moment = require('moment');

let database = [
    ['E', moment.utc(new Date()).add(-5, 'days').toDate(), null, null, '4FD034B0A6140FE7ACB170F7530E078201D46992', 'unknown', '/C=US/CN=lxer.com'],
    ['R', moment.utc(new Date()).add(200, 'days').toDate(), moment.utc(new Date()).toDate(), 'certificateHold', '5AB123C0D2341FE7ACB170F7530E078201D46993', 'unknown', '/C=US/CN=test.com'],
    ['V', moment.utc(new Date()).add(340, 'days').toDate(), null, null, '6BC234D0E3452FE7ACB170F7530E078201D46994', 'unknown', '/C=US/CN=example.com'],
    ['R', moment.utc(new Date()).add(290, 'days').toDate(), moment.utc(new Date()).add(-1, 'days').toDate(), 'keyCompromise', '7CD345E0F4563FE7ACB170F7530E078201D46995', 'unknown', '/C=US/CN=foobar.com'],
]

console.log(openssl.crl.generateIndex(database));