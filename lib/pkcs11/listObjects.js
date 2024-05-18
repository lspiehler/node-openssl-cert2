const binary = require('../binary');
const parseOutput = require('./parseOutput');

const listObjects = function(params, callback) {
    let cmd = ['--list-objects'];
    if(params) {
        if(params.modulePath) {
            cmd.push('--module ' + params.modulePath);
        }
        if(params.slotid) {
            cmd.push('--slot ' + params.slotid);
        }
    }
    //console.log(cmd.join(' '));
    binary.pkcs11Tool.runCommand({cmd: cmd.join(' '), waitforstdout: false}, function(err, out) {
        if(err) {
            callback(err,{
                command: [out.command],
                data: out.stdout,
            });
        } else {
            const lines = out.stdout.toString().split('\n')
            const objects = parseOutput(lines);
            callback(false,{
                command: [out.command],
                data: objects,
            });
        }
    });
}

module.exports = listObjects;