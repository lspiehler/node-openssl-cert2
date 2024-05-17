const binary = require('../binary');
const pkcs11 = require('../pkcs11');
const common = require('../common');

var createSlot = function(params, callback) {
    pkcs11.listSlots({modulePath: params.modulePath}, function(err, slotout) {
        //console.log(cmd);
        if(err) {
            callback(err, false);
        } else {
            var originalslotid = slotout.data.length - 1;
            let label = pkcs11.prepLabel(params.label);
            //console.log(label)
            let cmd = ['--module ' + params.modulePath + ' --slot ' + originalslotid + ' --init-token --label ' + label + ' --so-pin ' + params.sopin];
            //let cmd = ['--module ' + params.modulePath --slot ' + originalslotid + ' --init-token --label \'' + params.label + '\' --so-pin ' + params.sopin];
            //console.log('look here');
            //console.log(cmd);
            binary.pkcs11Tool.runCommand({cmd: cmd.join(' ')}, function(err, out1) {
                //console.log(out);
                if(err) {
                    callback(err, false);
                } else {
                    pkcs11.listSlots({modulePath: params.modulePath}, function(err, slotout) {
                        //console.log(cmd);
                        if(err) {
                            callback(err, false);
                        } else {
                            let newslotid;
                            let slotindex = 0;
                            for(let i = 0; i <= slotout.data.length - 1; i++) {
                                if(slotout.data[i].id==originalslotid) {
                                    slotindex = i;
                                    newslotid = slotout.data[i].hexid;
                                    break;
                                }
                            }
                            let cmd = ['--module ' + params.modulePath + ' --slot ' + newslotid + ' --login --login-type so --so-pin ' + params.sopin + ' --init-pin --pin ' + params.pin];
                            //console.log('look here');
                            //console.log(cmd);
                            binary.pkcs11Tool.runCommand({cmd: cmd.join(' ')}, function(err, out2) {
                                //console.log(out);
                                if(err) {
                                    callback(err,{
                                        command: common.flatten([out1.command.replace('--so-pin ' + params.sopin, '--so-pin hidden'), out2.command.replace('--so-pin ' + params.sopin, '--so-pin hidden').replace('--pin ' + params.pin, '--pin hidden')]),
                                        data: out2.stdout.toString()
                                    });
                                } else {
                                    callback(false,{
                                        command: common.flatten([out1.command.replace('--so-pin ' + params.sopin, '--so-pin hidden'), out2.command.replace('--so-pin ' + params.sopin, '--so-pin hidden').replace('--pin ' + params.pin, '--pin hidden')]),
                                        data: slotout.data[slotindex]
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

module.exports = createSlot;