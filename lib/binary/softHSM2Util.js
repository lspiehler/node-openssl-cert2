const { spawn } = require( 'child_process' );
var path = 'softhsm2-util';
var debug = false;

const runCommand = function(params, callback) {
    const stdoutbuff = [];
    const stderrbuff = [];
    var code;
    var exited = false;
    var stdoutrecvd = false;
    var stderrrecvd = false;

    if(params.waitforstdout === false) {
        //don't wait for stdout because none is expected
        stdoutrecvd = true;
    }

    //console.log(params.cmd);
    var handleExit = function() {
        var out = {
            command: 'openssl ' + params.cmd,
            stdout: Buffer.concat(stdoutbuff),
            stderr: Buffer.concat(stderrbuff),
            exitcode: code
        }
        if (code != 0) {
            callback(Buffer.concat(stderrbuff).toString(), out);
        } else {
            callback(false, out);
        }
    }
    
    try {
        let env = {}
        if(params.env) {
            env = params.env
        }
        if(debug===true) {
            console.log('Running command: ' + params.cmd);
        }
        const softHSM2Util = spawn( path, params.cmd.split(' '), {cwd: params.cwd, env: env } );

        if(debug===true) {
            console.log("Command executed as PID: " + softHSM2Util.pid);
        }

        softHSM2Util.on('spawn', function(err) {
            if(params.hasOwnProperty('stdin')) {
                if(params.stdin) {
                    softHSM2Util.stdin.write(params.stdin);
                    softHSM2Util.stdin.end();
                }
            }
        });

        softHSM2Util.stdin.on('error', function(err) {
            var out = {
                command: 'softHSM2Util ' + params.cmd,
                stdout: Buffer.concat(stdoutbuff),
                stderr: Buffer.concat(stderrbuff),
                exitcode: code
            }
            callback(e, out);
            return;
        });
        
        softHSM2Util.stdout.on('data', function(data) {
            stdoutrecvd = true;
            stdoutbuff.push(data);
            if(debug===true) {
                console.log('Received stdout from ' + softHSM2Util.pid + ': ' + data.toString())
            }
            if(exited && code == 0) {
                handleExit();
            }
        });

        softHSM2Util.on('error', function(err) {
            //console.log(err);
            var out = {
                command: 'softHSM2Util ' + params.cmd,
                stdout: Buffer.concat(stdoutbuff),
                stderr: Buffer.concat(stderrbuff),
                exitcode: code
            }
            callback(err, out);
            return;
        });
        
        softHSM2Util.stderr.on('data', function(data) {
            stderrrecvd = true;
            stderrbuff.push(data);
            if(debug===true) {
                if(containsOnly(data.toString(), ["+", "*", "."]) == false) {
                    console.log('Received stderr from ' + softHSM2Util.pid + ': ' + data.toString())
                }
            }
            if(exited && code != 0) {
                handleExit();
            }
        });
        
        softHSM2Util.on('close', function(ecode, signal) {
            exited = true;
            //console.log(ecode);
            code = ecode;
            if(stdoutrecvd && ecode == 0) {
                handleExit();
            }

            if(stderrrecvd && ecode != 0) {
                handleExit();
            }
            
        });
    } catch(e) {
        var out = {
            command: 'softHSM2Util ' + params.cmd,
            stdout: Buffer.concat(stdoutbuff),
            stderr: Buffer.concat(stderrbuff),
            exitcode: code
        }
        callback(e, out);
        return;
    }
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