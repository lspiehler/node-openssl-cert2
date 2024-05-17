var prepLabel = function(str) {
    let label;
    //console.log(params.label);
    if(str) {
        if(str != '') {
            label = str.split(' ').join('\\ ');
        } else {
            label = str;
        }
    } else {
        label = str;
    }

    return label;
}

module.exports = prepLabel;