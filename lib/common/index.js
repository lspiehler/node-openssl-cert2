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
      }
}