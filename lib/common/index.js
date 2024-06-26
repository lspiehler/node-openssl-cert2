const fs = require('fs');
const providers = require('../providers');

module.exports = {
  flatten: function(array, mutable) {
    var nodes = (mutable && array) || array.slice(); // return a new array.
    var flattened = [];
  
    for (var node = nodes.shift(); node !== undefined; node = nodes.shift()) {
      if (Array.isArray(node)) {
        nodes.unshift.apply(nodes, node);
      } else {
        flattened.push(node);
      }
    }
  
    return flattened;
  },
  writeIfNotFalsy: function(path, data, callback) {
    if(data) {
      fs.writeFile(path, data, function(err) {
        if(err) {
            callback(err);
        } else {
          callback(false);
        }
      });
    } else {
      callback(false);
    }
  },
  checkProvider: function(provider, callback) {
    providers.get(function(err, providers) {
      if(err) {
          callback(false);
      } else {
        //console.log(providers);
        //console.log(Object.keys(providers.data));
        let providerfound = false;
        let keys = Object.keys(providers.data);
        for(let i = 0; i < keys.length; i++) {
          if(providers.data[keys[i]].name == provider) {
            providerfound = true;
            break;
          }
        }
        callback(providerfound);
      }
    });
  }
}