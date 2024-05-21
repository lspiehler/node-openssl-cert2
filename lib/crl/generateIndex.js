const moment = require('moment');

const generateIndex = function(revoke) {
    const date = new Date();
    let database = [];
    const serials = Object.keys(revoke);
    //console.log(serials);
    for(let i = 0; i < serials.length; i++) {
        let validity = 'V';
        if(revoke[serials[i]]) {
            validity = 'R';
        }
        database.push(validity + '\t' + moment(date).add(1, 'days').format('YYMMDDHHmmss') + 'Z\t' + moment(date).format('YYMMDDHHmmss') + 'Z,' + revoke[serials[i]] + '\t' + serials[i] + '\tunknown\t/C=US');
    }
    database.push('');
    return database;
}

module.exports = generateIndex;