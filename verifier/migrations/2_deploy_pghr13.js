var Verifier = artifacts.require("VerifiyPGHR13");

module.exports = function(deployer) {
	deployer.deploy(Verifier);
};