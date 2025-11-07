const { spawn } = require( 'child_process' );
const { console } = require('inspector');
var path = 'pkcs11-tool';
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
            command: 'pkcs11-tool ' + params.cmd,
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
        let env = process.env;
        if(params.env) {
            env = {...process.env, ...params.env};
        }
        if(debug===true) {
            console.log('Running command: ' + params.cmd);
        }
        const pkcs11tool = spawn( path, params.cmd.split(' '), {cwd: params.cwd, env: env } );

        if(debug===true) {
            console.log("Command executed as PID: " + pkcs11tool.pid);
        }

        pkcs11tool.on('spawn', function() {
            if(params.hasOwnProperty('stdin')) {
                if(params.stdin) {
                    pkcs11tool.stdin.write(Buffer.from(params.stdin), function() {
                        pkcs11tool.stdin.end();
                    })
                }
            }
        });

        pkcs11tool.stdin.on('error', function(e) {
            var out = {
                command: 'pkcs11tool ' + params.cmd,
                stdout: Buffer.concat(stdoutbuff),
                stderr: Buffer.concat(stderrbuff),
                exitcode: code
            }
            callback(e, out);
            return;
        });
        
        pkcs11tool.stdout.on('data', function(data) {
            stdoutrecvd = true;
            stdoutbuff.push(data);
            if(debug===true) {
                console.log('Received stdout from ' + pkcs11tool.pid + ': ' + data.toString())
            }
        });

        pkcs11tool.on('error', function(err) {
            //console.log(err);
            var out = {
                command: 'pkcs11tool ' + params.cmd,
                stdout: Buffer.concat(stdoutbuff),
                stderr: Buffer.concat(stderrbuff),
                exitcode: code
            }
            callback(err, out);
            return;
        });
        
        pkcs11tool.stderr.on('data', function(data) {
            stderrrecvd = true;
            stderrbuff.push(data);
            if(debug===true) {
                if(containsOnly(data.toString(), ["+", "*", "."]) == false) {
                    console.log('Received stderr from ' + pkcs11tool.pid + ': ' + data.toString())
                }
            }
        });
        
        pkcs11tool.on('close', function(ecode, signal) {
            exited = true;
            //console.log(ecode);
            code = ecode;
            /*if(stdoutrecvd && ecode == 0) {
                handleExit();
            }

            if(stderrrecvd && ecode != 0) {*/
                handleExit();
            //}
            
        });
    } catch(e) {
        var out = {
            command: 'pkcs11tool ' + params.cmd,
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
    setPath: function(pkcs11toolpath) {
        path = pkcs11toolpath;
    }
}