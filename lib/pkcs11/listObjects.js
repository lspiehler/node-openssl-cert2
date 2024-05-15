const binary = require('../binary');

const listObjects = function(params, callback) {
    let objects = []
    let cmd = ['--list-objects'];
    if(params) {
        if(params.modulePath) {
            cmd.push('--module ' + params.modulePath);
        }
        if(params.slotid) {
            cmd.push('--slot ' + params.slotid);
        }
    }
    binary.pkcs11Tool.runCommand({cmd: cmd.join(' ')}, function(err, out) {
        if(err) {
            callback(err,{
                command: common.flatten([object.command + ' --output-file cert.der', pem.command]),
                data: out.stdout,
            });
        } else {
            let object = {};
            let objectexist = false;
            let interesting = false;
            let interestingobjects = ['CERTIFICATE OBJECT', 'PUBLIC KEY OBJECT']
            let lines = out.stdout.toString().split('\n');
            //console.log(lines);
            for(let i = 0; i <= lines.length - 2; i++) {
                //console.log(lines[i]);
                if(lines[i][0]==' ') {
                    //console.log('property');
                    if(interesting) {
                        //console.log('pay attention');
                        let examineproperty = lines[i].split(':');
                        let key = examineproperty.shift().trim();
                        if(key.toUpperCase()=='SUBJECT') {
                            object[key] = examineproperty.join(':').replace('DN:' ,'').trim();
                        } else if(key.toUpperCase()=='USAGE') {
                            object[key] = examineproperty.join(':').trim().split(', ');
                        } else {
                            object[key] = examineproperty.join('').trim();
                        }
                    } else {
                        //console.log('ignore');
                    }
                } else {
                    if(objectexist===true) {
                        objects.push(object);
                        object = {};
                    }
                    let examineobject = lines[i].split('; ');
                    if(interestingobjects.includes(examineobject[0].toUpperCase())) {
                        objectexist = true;
                        interesting = true;
                        //console.log(examineobject);
                        object.type = examineobject[0]
                        object.detail = examineobject[1].replace('type = ', '');
                    } else {
                        interesting = false;
                    }
                }
            }
            if(objectexist) {
                objects.push(object);
            }
            callback(false,{
                command: [out.command],
                data: objects,
            });
        }
    });
}

module.exports = listObjects;