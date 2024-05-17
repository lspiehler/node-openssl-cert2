const parseOutput = function(output) {
    let objects = []
    let object = {};
    let objectexist = false;
    let interesting = false;
    let interestingobjects = ['CERTIFICATE OBJECT', 'PUBLIC KEY OBJECT', 'PRIVATE KEY OBJECT']
    //console.log(output);
    for(let i = 0; i <= output.length - 2; i++) {
        //console.log(output[i]);
        if(output[i][0]==' ') {
            //console.log('property');
            if(interesting) {
                //console.log('pay attention');
                let examineproperty = output[i].split(':');
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
            let examineobject = output[i].split('; ');
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
    return objects;
}

module.exports = parseOutput;