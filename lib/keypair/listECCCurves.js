const binary = require('../binary');
const common = require('../common');

let listECCCurves = function(callback) {
    let cmd = ['ecparam -list_curves'];
    binary.openssl.runCommand({cmd: cmd.join(' ')}, function(err, out) {
        if(err) {
            callback(err, false, null);
        } else {
            let lines = out.stdout.toString().split('\n');
            let curves = Array();
            //last line of output was blank on current version of openssl
            for(let i = 0; i <= lines.length - 2; i++) {
                if(lines[i].indexOf(':') >= 0) {
                    let curve = {};
                    let line = lines[i].split(':');
                    curve['curve'] = line[0].trim(' ');
                    if(line[1].trim(' ')!='') {
                        curve['description'] = line[1].trim(' ');
                    } else {
                        curve['description'] = lines[i + 1].replace('\t','').replace('\r','');
                    }
                    curves.push(curve);
                }
            }
            callback(false,{
                command: [out.command],
                data: curves
            });
        }
    });
}

module.exports = listECCCurves;