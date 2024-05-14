const { spawn } = require( 'child_process' );
var path = 'openssl';
var version = null;
var debug = false;

let getVersion = function(callback) {
    runCommand({cmd: "version"}, function(err, version) {
        if(err) {
            callback(err, false);
        } else {
            callback(false, version.stdout.toString().split(' ')[1]);
        }
    })
}

let normalizeCommand = function(command) {
    let cmd = command.split(' ');
    let outcmd = [];
    let cmdbuffer = [];
    for(let i = 0; i <= cmd.length - 1; i++) {
        if(cmd[i].charAt(cmd[i].length - 1) == '\\') {
            cmdbuffer.push(cmd[i]);
        } else {
            if(cmdbuffer.length > 0) {
                outcmd.push(cmdbuffer.join(' ') + ' ' + cmd[i]);
                cmdbuffer.length = 0;
            } else {
                outcmd.push(cmd[i]);
            }
        }
    }
    return outcmd;
}

function containsOnly(str, set) {
    return str.split('').every(function(ch) {
        return set.indexOf(ch) !== -1;
    });
}

let runCommand = function(params, callback) {
    const stdoutbuff = [];
    const stderrbuff = [];
    var code;
    var exited = false;
    var stdoutrecvd = false;
    var stderrrecvd = false;
    var allowexitafterstderronly = false;

    //console.log(params.cmd);

    if(params.cmd.indexOf(' -out ') >= 0) {
        //don't wait for stdout because none is expected
        stdoutrecvd = true;
    }

    if(params.waitforstdout === false) {
        //don't wait for stdout because none is expected
        stdoutrecvd = true;
    }

    if(params.exitafterstderr === false) {
        //don't wait for stdout because none is expected
        allowexitafterstderronly = true;
    }

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
        const openssl = spawn( path, normalizeCommand(params.cmd), {cwd: params.cwd, env: env } );

        if(debug===true) {
            console.log("Command executed as PID: " + openssl.pid);
        }

        openssl.on('spawn', function(err) {
            if(params.hasOwnProperty('stdin')) {
                if(params.stdin) {
                    openssl.stdin.write(params.stdin);
                    openssl.stdin.end();
                }
            }
        });

        openssl.stdin.on('error', function(err) {
            var out = {
                command: 'openssl ' + params.cmd,
                stdout: Buffer.concat(stdoutbuff),
                stderr: Buffer.concat(stderrbuff),
                exitcode: code
            }
            callback(e, out);
            return;
        });
        
        openssl.stdout.on('data', function(data) {
            stdoutrecvd = true;
            stdoutbuff.push(data);
            if(debug===true) {
                console.log('Received stdout from ' + openssl.pid + ': ' + data.toString())
            }
            if(exited && code == 0) {
                handleExit();
            }
        });

        openssl.on('error', function(err) {
            //console.log(err);
            var out = {
                command: 'openssl ' + params.cmd,
                stdout: Buffer.concat(stdoutbuff),
                stderr: Buffer.concat(stderrbuff),
                exitcode: code
            }
            callback(err, out);
            return;
        });
        
        openssl.stderr.on('data', function(data) {
            stderrrecvd = true;
            stderrbuff.push(data);
            if(debug===true) {
                if(containsOnly(data.toString(), ["+", "*", "."]) == false) {
                    console.log('Received stderr from ' + openssl.pid + ': ' + data.toString())
                }
            }
            if(exited && code != 0) {
                handleExit();
            }
        });
        
        openssl.on('exit', function(ecode) {
            exited = true;
            code = ecode;
            if(stdoutrecvd && ecode == 0) {
                handleExit();
            }

            if(allowexitafterstderronly) {
                if(stderrrecvd && ecode == 0) {
                    handleExit();
                }
            }

            if(stderrrecvd && ecode != 0) {
                handleExit();
            }
            
        });
    } catch(e) {
        var out = {
            command: 'openssl ' + params.cmd,
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
    setPath: function(opensslpath) {
        path = opensslpath;
    },
    getVersion: function(callback) {
        if(version) {
            callback(false, version);
        } else {
            getVersion(function(err, openssl_version) {
                if(err) {
                    callback(err, false);
                } else {
                    version = openssl_version
                    callback(false, openssl_version);
                }
            })
        }
    }
}