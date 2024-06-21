const binary = require('../binary');
var cachedproviders = null;

let get = function(callback) {
    var cmd = ['list -providers'];
    if(cachedproviders) {
        callback(false,{
            command: ['openssl second ' + cmd.join()],
            data: cachedproviders,
        });
    } else {
        binary.openssl.runCommand({cmd: cmd.join(' ')}, function(err, out) {
            if(err) {
                callback(err,{
                    command: [out.command],
                    data: out.stdout.toString(),
                });
            } else {
                let lines = out.stdout.toString().split('\n');
                let providers = {};
                let index;
                for(let i = 1; i < lines.length - 1; i++) {
                    let line = lines[i].split(':');
                    if(line.length < 2) {
                        index = line[0].trim();
                        providers[index] = {};
                    } else {
                        providers[index][line[0].trim()] = line[1].trim()
                    }
                }
                cachedproviders = providers;
                callback(false,{
                    command: [out.command],
                    data: providers,
                });
            }
        });
    }
}

module.exports = get;