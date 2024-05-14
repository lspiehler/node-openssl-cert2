const binary = require('../binary');
const config = require('../config');
const tmp = require('tmp');
const fs = require('fs');
const moment = require('moment');

function generateTextDatabase(revoke) {
    const date = new Date();
    let database = [];
    const serials = Object.keys(revoke);
    //console.log(serials);
    for(let i = 0; i < serials.length; i++) {
        database.push('R\t' + moment(date).add(1, 'days').format('YYMMDDHHmmss') + 'Z\t' + moment(date).format('YYMMDDHHmmss') + 'Z,' + revoke[serials[i]] + '\t' + serials[i] + '\tunknown\t/C=US');
    }
    database.push('');
    return database;
    /*if(results) {
        //console.log(results);
        //console.log(results[index]['public_key']);
        openssl.getCertInfo(results[index].public_key, function(err, attrs, cmd) {
            if(err) {
                //console.log(attrs);
                callback(err, false);
            } else {
                database.push('R\t'+ results[index].opensslvalidto +'\t' + results[index].opensslrevokedate + ',' + results[index].reason + '\t' + results[index].serial.toUpperCase() + '\tunknown\t' + openssl.getDistinguishedName(attrs.subject));
                if(index >= results.length - 1) {
                    //console.log('this is true');
                    callback(null, database.join('\r\n') + '\r\n');
                } else {
                    generateTextDatabase(results, database, index + 1, callback);
                }
            }
        });
    } else {
        callback(null, '');
    }*/
}

var generate = function(params, callback) {
    let password = '_PLAIN_'
    const indexdb = generateTextDatabase(params.revoked);
    tmp.dir({unsafeCleanup: true}, function _tempDirCreated(err, path, cleanupCallback1) {
        if(err) {
            callback(err, false);
        } else {
            fs.writeFile(path + '/ca.key', params.key, function(err) {
                if(err) {
                    cleanupCallback1();
                    callback(err, false);
                } else {
                    fs.writeFile(path + '/ca.crt', params.ca, function(err) {
                        if(err) {
                            cleanupCallback1();
                            callback(err, false);
                        } else {
                            fs.writeFile(path + '/index.txt', indexdb.join('\r\n'), function(err) {
                                if(err) {
                                    cleanupCallback1();
                                    callback(err, false);
                                } else {
                                    fs.writeFile(path + '/index.txt.attr', 'unique_subject = no', function(err) {
                                        if(err) {
                                            cleanupCallback1();
                                            callback(err, false);
                                        } else {
                                            const baseconfig = {
                                                hash: 'sha256',
                                                subject: {
                                                    countryName: 'US'
                                                }
                                            }
                                            let osslpath;
                                            if(path.indexOf('\\') >= 0) {
                                                osslpath = path.split('\\').join('\\\\')
                                            } else {
                                                osslpath = path;
                                            }
                                            config.generate(baseconfig, true, osslpath, function(err, config) {
                                                if(err) {
                                                    cleanupCallback1();
                                                    callback(err,{
                                                        command: null,
                                                        data: null
                                                    });
                                                    return false;
                                                } else {
                                                    fs.writeFile(path + '/config.txt', config.join('\r\n'), function(err) {
                                                        if(err) {
                                                            cleanupCallback1();
                                                            callback(err, false);
                                                        } else {
                                                            let cmd = ['ca -config config.txt' + ' -gencrl -crldays ' + params.crldays.toString()];
                                                            if(params.password) {
                                                                //env['PASS'] = params.password;
                                                                password = params.password;
                                                                cmd.push('-passin stdin');
                                                            } else {
                                                                //env['PASS'] = '_PLAIN_'
                                                                cmd.push('-passin stdin');
                                                            }
                                                            binary.openssl.runCommand({ cmd: cmd.join(' '), stdin: password, cwd: path}, function(err, out) {
                                                                if(err) {
                                                                    callback(err, {
                                                                        command: [out.command.replace('-passin stdin', '-passin pass:hidden')],
                                                                        data: out.stdout.toString(),
                                                                        files: {
                                                                            config: config.join('\r\n'),
                                                                            index: indexdb.join('\r\n')
                                                                        }
                                                                    });
                                                                    //console.log(path);
                                                                    cleanupCallback1();
                                                                } else {
                                                                    callback(false, {
                                                                        command: [out.command.replace('-passin stdin', '-passin pass:hidden')],
                                                                        data: out.stdout.toString(),
                                                                        files: {
                                                                            config: config.join('\r\n'),
                                                                            index: indexdb.join('\r\n')
                                                                        }
                                                                    });
                                                                    //console.log(path);
                                                                    cleanupCallback1();
                                                                }
                                                            });
                                                        }
                                                    });
                                                }
                                            });
                                        }
                                    });
                                }
                            });
                        }
                    });
                }
            });
        }
    });
}

module.exports = generate;