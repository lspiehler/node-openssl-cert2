const { spawn } = require( 'child_process' );
var path = 'pkcs11-tool';
var libdir = '/usr/lib';
var debug = false;

var runCommand = function(params, callback) {
    const stdoutbuff = [];
    const stderrbuff = [];
    var terminate = false;
    
    if(params.cmd.indexOf('s_client') >= 0) {
        terminate = true;
    }
    
    const pkcs11tool = spawn( path, params.cmd.split(' '));
    
    pkcs11tool.stdout.on('data', function(data) {
        stdoutbuff.push(data.toString());
        /*//pkcs11tool.stdin.setEncoding('utf-8');
        setTimeout(function() {
            //pkcs11tool.stdin.write("QUIT\r");
            //console.log('QUIT\r\n');
            //pkcs11tool.stdin.end();
            pkcs11tool.kill();
        }, 1000);*/
        if(terminate) {
            //if(data.toString().indexOf('Verify return code: 0 (ok)') >= 0 ) {
            if(stdoutbuff.join('').toString().indexOf('Verify return code: ') >= 0 ) {
                pkcs11tool.kill();
            }
        }
    });

    /*pkcs11tool.stdout.on('end', function(data) {
        stderrbuff.push(data.toString());
    });*/
    
    pkcs11tool.stderr.on('data', function(data) {
        stderrbuff.push(data.toString());
    });
    
    pkcs11tool.on('exit', function(code) {
        if(terminate && code==null) {
            code = 0;
        }
        var out = {
            command: 'pkcs11-tool ' + params.cmd,
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