const https = require('https');
const fs = require('fs');

const buildNameMappings = function() {
    var httpRequest = function(params, callback) {
        const req = https.request(params.options, res => {
            var resp = [];

            res.on('data', function(data) {
                resp.push(data);
            });

            res.on('end', function() {
                callback(false, {statusCode: res.statusCode, options: params.options, headers: res.headers, body: Buffer.concat(resp).toString()});
            });
        })

        req.on('error', function(err) {
            //console.log(err);
            callback(false, {statusCode: false, options: params.options, headers: false, body: JSON.stringify(err)});
        })

        if(params.options.method=='POST') {
            req.write(JSON.stringify(params.body));
        }

        req.end()
    }

    let options = {
        host: 'raw.githubusercontent.com',
        //path: '/openssl/openssl/OpenSSL_1_1_1-stable/crypto/objects/objects.txt',
        path: '/openssl/openssl/openssl-3.3/crypto/objects/objects.txt',
        method: 'GET'
    }

    //stage old names
    var oids = {
        "Microsoft Universal Principal Name": "msUPN",
        "Microsoft Smartcardlogin": "msSmartcardLogin"
    }

    /*var forward = {
        "msUPN": "Microsoft Universal Principal Name",
        "msSmartcardLogin": "Microsoft Smartcardlogin"
    }*/

    httpRequest({options: options}, function(err, resp) {
        if(err) {
            console.error(err);
        } else {
            let lines = resp.body.split('\n');
            for(let i = 0; i <= lines.length - 1; i++) {
                if(lines[i] != '' && lines[i].charAt(0)!='#' && lines[i].charAt(0)!='!') {
                    //console.log(lines[i].charAt(0);
                    let line = lines[i].split(':');
                    let key;
                    let value;
                    //console.log(lines[i]);
                    //console.log(line);
                    if(line.length == 3) {
                        key = line[2].trim();
                        value = line[1].trim();
                    } else {
                        key = line[1].trim();
                        value = line[1].trim();
                    }
                    if(value != '') {
                        oids[key] = value;
                        //forward[value] = key;
                    } else {
                        //oids[key] = key;
                    }
                }
            }
            //const backwardpath = __dirname + '/nameMappingsBackward.js';
            const path = __dirname + '/nameMappings.js';
            const output = 'module.exports = ' + JSON.stringify(oids, null, 2);
            //const forwardoutput = 'module.exports = ' + JSON.stringify(forward, null, 2);
            fs.writeFile(path, output, function(err) {
                if(err) {
                    console.log(err);
                } else {
                    /*fs.writeFile(forwardpath, forwardoutput, function(err) {
                        if(err) {
                            console.log(err);
                        } else {*/
                            const keys = Object.keys(oids);
                            console.error('Successfully wrote ' + keys.length + ' name mappings to ' + path);
                        //}
                    //});
                }
            });
        }
    });
} 

//module.exports = buildNameMappings;
buildNameMappings();