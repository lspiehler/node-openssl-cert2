const binary = require('../binary');
var net = require('net');

var tcpCheck = function(host, port, callback) {
    let option = {
        host: host,
        port: port
    }
    
    var client = net.createConnection(option, function () {
        //console.log('Connection local address : ' + client.localAddress + ":" + client.localPort);
        //console.log('Connection remote address : ' + client.remoteAddress + ":" + client.remotePort);
    });
    
    client.setTimeout(3000);
    client.setEncoding('utf8');
    
    client.on('timeout', function () {
        //console.log('Client connection timeout. ');
        client.destroy();
        callback('Timed out connecting to host ' + host + ' on port ' + port, 'Timed out connecting to host ' + host + ' on port ' + port);
    });
    
    client.on('connect', function () {
        //console.log('Client connected. ');
        client.destroy();
        callback(false, 'Successfully established connection.')
    });
    
    client.on('error', function (e) {
        //console.log('Client connection error: ' + e);
        if(e.code=='ENOTFOUND') {
            callback('Failed to lookup domain name ' + host, 'Failed to lookup domain name ' + host)
        } else if(e.code=='ECONNRESET') {
            //let openssl handle errors for resets
            callback(false, 'Connection was reset.');
        } else {
            callback('Failed connecting to host ' + host + ' on port ' + port, 'Failed connecting to host ' + host + ' on port ' + port);
        }
    });
    
    client.on('end', function () {
        //console.log('Client connection timeout. ');
        //callback(false, 'Successfully established connection.')
    });
    
    client.on('close', function () {
        //console.log('Client connection closed. ');
        //callback(false, 'Successfully established connection.')
    });
    
}

var getCertFromNetwork = function(options, callback) {
    const begin = '-----BEGIN CERTIFICATE-----';
    const end = '-----END CERTIFICATE-----';
    options.port = typeof options.port !== 'undefined' ? options.port : 443;
    options.starttls = typeof options.starttls !== 'undefined' ? options.starttls : false;
    options.protocol = typeof options.protocol !== 'undefined' ? options.protocol : 'https';
    
    var param;
    
    if(options.protocol=='https') {
        param = ' -servername ' + options.hostname;
    } else if(options.starttls){
        param = ' -starttls ' + options.protocol;
    } else {
        param = '';
    }
    let cmd = ['s_client -showcerts -connect ' + options.hostname + ':' + options.port + param];
    if(options.groups) {
        cmd.push('-groups ' + options.groups.join(":"));
    }
    if(options.sigalgs) {
        cmd.push('-sigalgs ' + options.sigalgs.join(":"));
    }
    tcpCheck(options.hostname, options.port, function(err, result) {
        if(err) {
            callback(err, {
                command: [cmd.join(' ')],
                data: false
            });
        } else {
            binary.openssl.runCommand({cmd: cmd.join(' '), stdin: 'Q\n'}, function(err, out) {
                var placeholder = out.stdout.toString().indexOf(begin);
                var certs = [];
                var endoutput = false;
                if(placeholder <= 0) {
                    endoutput = true;
                    if(err) {
                        callback(err, {
                            command: [out.command],
                            data: false
                        });
                    } else {
                        callback('No certificate found in openssl command response', {
                            command: [out.command],
                            data: false
                        });
                    }
                } else {
                    var shrinkout = out.stdout.toString().substring(placeholder);
                    //console.log(shrinkout);
                    while(!endoutput) {
                        let endofcert = shrinkout.indexOf(end);
                        certs.push(shrinkout.substring(0, endofcert) + end);
                        shrinkout = shrinkout.substring(endofcert); 
                        
                        placeholder = shrinkout.indexOf(begin);
                        //console.log(placeholder);
                        if(placeholder <= 0) {
                            endoutput = true;
                        } else {
                            shrinkout = shrinkout.substring(placeholder);
                        }
                    }
                    callback(false, {
                        command: [out.command],
                        data: certs
                    });
                }
            });
        }
    });
}

module.exports = getCertFromNetwork;