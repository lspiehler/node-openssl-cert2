const binary = require('../binary');

const listSlots = function(params, callback) {
    let slots = []
    let cmd = ['--list-slots'];
    if(params) {
        if(params.modulePath) {
            cmd.push('--module ' + params.modulePath);
        }
    }
    binary.pkcs11Tool.runCommand({cmd: cmd.join(' ')}, function(err, out) {
        if(err) {
            if(out.stderr.indexOf('No slots') == 0) {
                callback(false, [], out);
            } else {
                callback(err, false, out);
            }
        } else {
            let slot = {};
            let slotsexist = false;
            let lines = out.stdout.split('\n');
            for(let i = 1; i <= lines.length - 2; i++) {
                if(lines[i].indexOf('Slot') == 0) {
                    if(slotsexist) {
                        slots.push(slot);
                        slot = {}
                    }
                    slotsexist = true;
                    slot.id = lines[i].split(' (0x')[0].substring(5);
                    //slot.id = parseInt(lines[i].split('): ')[0].substring(8), 16);
                    slot.hexid = lines[i].split('): ')[0].substring(8);
                    slot.name = lines[i].split('): ')[1]
                    //console.log(slot);
                } else {
                    let kvp = lines[i].split(':');
                    if(kvp[0].trim()=='token flags') {
                        slot[kvp.shift().trim()] = kvp.join(':').trim().split(', ');
                    } else {
                        slot[kvp.shift().trim()] = kvp.join(':').trim();
                    }
                    //console.log(kvp);
                }
            }
            if(slotsexist) {
                slots.push(slot);
            }
            callback(false, slots, out);
        }
    });
}

module.exports = listSlots;