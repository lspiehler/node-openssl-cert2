const { spawn } = require( 'child_process' );
var path = 'openssl';
var version = null;
var debug = false;

const getVersion = function(callback) {
    runCommand({cmd: "version"}, function(err, version) {
        if(err) {
            callback(err, false);
        } else {
            callback(false, version.stdout.toString().split(' ')[1]);
            // callback(false, '1.1');
        }
    })
}

const normalizeCommand = function(command) {
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

const runCommand = function(params, callback) {
    const stdoutbuff = [];
    const stderrbuff = [];
    var code;
    var stdoutrecvd = false;
    var stderrrecvd = false;

    //console.log(params.cmd);

    var handleExit = function(signal) {
        var out = {
            command: 'openssl ' + params.cmd,
            stdout: Buffer.concat(stdoutbuff),
            stderr: Buffer.concat(stderrbuff),
            exitcode: code
        }
        // console.log('Process exited with code ' + code + ' and signal ' + signal);
        if(code === null) {
            callback('Process terminated with null exit code. Signal was ' + signal, out);
        } else {
            if (code != 0) {
                callback(Buffer.concat(stderrbuff).toString(), out);
            } else {
                callback(false, out);
            }
        }
    }
    
    try {
        let env = process.env;
        if(params.env) {
            env = {...process.env, ...params.env};
        }
        if(debug===true) {
            console.log('Running command: ' + params.cmd);
        }
        const openssl = spawn( path, normalizeCommand(params.cmd), {cwd: params.cwd, env: env } );

        if(debug===true) {
            console.log("Command executed as PID: " + openssl.pid);
        }

        openssl.on('spawn', function() {
            if(params.hasOwnProperty('stdin')) {
                if(params.stdin) {
                    //console.log(openssl.stdin)
                    //openssl.stdin.setEncoding('utf-8');
                    //openssl.stdin.cork();
                    openssl.stdin.write(Buffer.from(params.stdin), function() {
                        openssl.stdin.end();
                    })
                    //openssl.stdin.uncork();
                    //openssl.stdin.drain();
                }
            }
        });

        openssl.stdin.on('error', function(e) {
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
        });
        
        openssl.on('close', function(ecode, signal) {
            exited = true;
            code = ecode;
            /*if(stdoutrecvd && ecode == 0) {
                handleExit();
            }

            if(allowexitafterstderronly) {
                if(stderrrecvd && ecode == 0) {
                    handleExit();
                }
            }

            if(stderrrecvd && ecode != 0) {*/
                handleExit(signal);
            //}
            
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