const { spawn } = require( 'child_process' );
var path = 'pkcs11-tool';
var libdir = '/usr/lib';
var debug = false;

var runCommand = function(params, callback) {
    const stdoutbuff = [];
    const stderrbuff = [];

    //console.log(params.cmd);
    
    const pkcs11tool = spawn( path, params.cmd.split(' '));
    
    pkcs11tool.stdout.on('data', function(data) {
        stdoutbuff.push(data);
    });

    /*pkcs11tool.stdout.on('end', function(data) {
        stderrbuff.push(data);
    });*/
    
    pkcs11tool.stderr.on('data', function(data) {
        stderrbuff.push(data);
    });
    
    pkcs11tool.on('exit', function(code) {
        if(code==null) {
            code = 0;
        }
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
    setPath: function(opensslpath) {
        path = opensslpath;
    },
    getLibDir: function() {
        return libdir;
    },
    setLibDir: function(dir) {
        libdir = dir;
    }
}