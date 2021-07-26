const assert = require('assert')

// const zkconsentjs = require('./build/Release/zkconsentjs');
const zkconsentjs = require('bindings')('zkconsentjs');

var zkconsent = new zkconsentjs.ZkConsentNode();

ask = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"
rho = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"
apk = zkconsent.prfapk(ask)
apk = apk.toUpperCase()
apk_expected = "2390c9e5370be7355f220b29caf3912ef970d828b73976ae9bfeb1402ce4c1f9".toUpperCase()
console.log('==== apk ====');
console.log(`ask   = ${ask}`);
console.log(`apk   = ${apk}`);
console.log();
assert((apk == apk_expected), "Unexpected apk");

nf  = zkconsent.prfconsentnf(ask, rho)
nf.toUpperCase()
nf_expected  = "ea43866d185e1bdb84713b699a2966d929d1392488c010c603e46a4cb92986f8".toUpperCase()
console.log('==== nf consent token ====');
console.log(`ask   = ${ask}`);
console.log(`rho   = ${rho}`);
console.log(`nf    = ${nf}`);
console.log();
assert((nf == nf_expected), "Unexpected apk");

console.log('==== nf User id token ====');
nfuid = zkconsent.prfuidnf(ask, rho)
nfuid.toUpperCase()
console.log(`ask   = ${ask}`);
console.log(`rho   = ${rho}`);
console.log(`nfuid = ${nfuid}`);
console.log();

console.log('==== nf study token ====');
nfstudy = zkconsent.prfstudynf(ask, rho)
nfstudy.toUpperCase()
console.log(`ask     = ${ask}`);
console.log(`rho     = ${rho}`);
console.log(`nfstudy = ${nfstudy}`);
console.log();
