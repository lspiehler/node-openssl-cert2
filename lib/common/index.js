const fs = require('fs');

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
  }
}