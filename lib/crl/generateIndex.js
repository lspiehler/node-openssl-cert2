const moment = require('moment');

const generateIndex = function(database) {
    // const date = new Date();
    // let database = [];
    // const serials = Object.keys(revoke);
    // //console.log(serials);
    // for(let i = 0; i < serials.length; i++) {
    //     let validity = 'V';
    //     if(revoke[serials[i]]) {
    //         validity = 'R';
    //     }
    //     database.push(validity + '\t' + moment(date).add(1, 'days').format('YYMMDDHHmmss') + 'Z\t' + moment(date).format('YYMMDDHHmmss') + 'Z,' + revoke[serials[i]] + '\t' + serials[i] + '\tunknown\t/C=US');
    // }
    // database.push('');
    // return database;
    let index = [];
    for(let i = 0; i < database.length; i++) {
        let entry = [];
        entry.push(database[i][0]); // V, R, E
        entry.push(moment(database[i][1]).utc().format('YYMMDDHHmmss') + 'Z');
        if(database[i][2]) {
            entry.push(moment(database[i][2]).utc().format('YYMMDDHHmmss') + 'Z,' + database[i][3]);
        } else {
            entry.push('');
        }
        entry.push(database[i][4]); // serial
        entry.push(database[i][5]); // file location
        entry.push(database[i][6]); // DN
        index.push(entry.join('\t'));
    }
    index.push('');
    return index.join('\n');
}

module.exports = generateIndex;