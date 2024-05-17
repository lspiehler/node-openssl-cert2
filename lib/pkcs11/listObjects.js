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
    binary.pkcs11Tool.runCommand({cmd: cmd.join(' ')}, function(err, out) {
        if(err) {
            callback(err,{
                command: common.flatten([object.command + ' --output-file cert.der', pem.command]),
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