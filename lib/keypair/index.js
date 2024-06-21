const convertECCToPKCS1 = require('./convertECCToPKCS1');
const convertRSAToPKCS1 = require('./convertRSAToPKCS1');
const convertToPKCS8 = require('./convertToPKCS8');
const generateECC = require('./generateECC');
const generateRSA = require('./generateRSA');
const generateOQSKey = require('./generateOQSKey');
const listECCCurves = require('./listECCCurves');
const getRSAPublicKey = require('./getRSAPublicKey');
const getECCPublicKey = require('./getECCPublicKey');

module.exports = {
    convertECCToPKCS1: convertECCToPKCS1,
    convertRSAToPKCS1: convertRSAToPKCS1,
    convertToPKCS8: convertToPKCS8,
    generateECC: generateECC,
    generateRSA: generateRSA,
    generateOQSKey: generateOQSKey,
    listECCCurves: listECCCurves,
    getRSAPublicKey: getRSAPublicKey,
    getECCPublicKey: getECCPublicKey
}