const binary = require('../binary');

const deleteSlot = function(params, callback) {
    let cmd = ['--delete-token --serial ' + params.serial];
    binary.softHSM2Util.runCommand({cmd: cmd.join(' ')}, function(err, out) {
        if(err) {
            callback(err, false);
        } else {
            callback(false, out.stdout.toString());
        }
    });
}

module.exports = deleteSlot;