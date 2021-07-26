// hello.js
// const nodegw = require('./build/Release/nodegw');
const nodegw = require('bindings')('nodegw');

var zkconsent = new nodegw.ZkConsentNode();

ask = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"
rho = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"
apk = zkconsent.prfapk(ask)
apk = apk.toUpperCase()
apk_expected = "2390c9e5370be7355f220b29caf3912ef970d828b73976ae9bfeb1402ce4c1f9".toUpperCase()

console.log(`ask   = ${ask}`);
console.log(`apk   = ${apk}`);
console.log(`Valid = ${(apk == apk_expected)}`);
console.log();


nf  = zkconsent.prfnf(ask, rho)
nf_expected  = "ea43866d185e1bdb84713b699a2966d929d1392488c010c603e46a4cb92986f8".toUpperCase()
console.log(`ask   = ${ask}`);
console.log(`rho   = ${rho}`);
console.log(`nf    = ${nf}`);
console.log(`Valid = ${(nf == nf_expected)}`);
console.log();
