const listSlots = require('./listSlots');
const listObjects = require('./listObjects');
const readObject = require('./readObject');
const prepLabel = require('./prepLabel');
const generateKeyPair = require('./generateKeyPair');
const importCertificate = require('./importCertificate');

module.exports = {
    listSlots: listSlots,
    listObjects: listObjects,
    readObject: readObject,
    prepLabel: prepLabel,
    generateKeyPair: generateKeyPair,
    importCertificate: importCertificate
}