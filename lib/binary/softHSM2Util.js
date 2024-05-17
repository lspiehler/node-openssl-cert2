const { spawn } = require( 'child_process' );
var path = 'softhsm2-util';
var debug = false;

const runCommand = function(params, callback) {
    const stdoutbuff = [];
    const stderrbuff = [];
    
    const softHSM2Util = spawn( path, params.cmd.split(' ') );
    
    softHSM2Util.stdout.on('data', function(data) {
        stdoutbuff.push(data.toString());
    });
    
    softHSM2Util.stderr.on('data', function(data) {
        stderrbuff.push(data.toString());
    });
    
    softHSM2Util.on('exit', function(code) {
        var out = {
            command: 'softhsm2-util ' + params.cmd,
            stdout: stdoutbuff.join(''),
            stderr: stderrbuff.join(''),
            exitcode: code
        }
        if (code != 0) {
            callback(stderrbuff.join(), out);
        } else {
            callback(false, out);
        }
    });
}

module.exports = {
    runCommand: function(params, callback) {
        runCommand(params, function(err, out) {
            if(err) {
                callback(err, out);
            } else {
                callback(false, out);
            }
        });
    },
    enableDebug: function() {
        debug = true;
    },
    disableDebug: function() {
        debug = false;
    },
    debug: function() {
        return debug;
    },
    getPath: function() {
        return path;
    },
    setPath: function(softhsm2utilpath) {
        path = softhsm2utilpath;
    }
}