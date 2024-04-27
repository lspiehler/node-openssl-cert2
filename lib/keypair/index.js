const fs = require('fs');
cachedexports = null;

if(cachedexports) {
    //console.log('using cache');
    module.exports = cachedexports;
} else {
    //console.log('processing');
    let files = fs.readdirSync(__dirname);
    cachedexports = {};
    for(let i = 0; i < files.length; i++) {
        if(files[i] != "index.js") {
            let lib = files[i].substring(0, files[i].length - 3);
            cachedexports[lib] = require('./' + lib);
        }
    }
    module.exports = cachedexports;
}