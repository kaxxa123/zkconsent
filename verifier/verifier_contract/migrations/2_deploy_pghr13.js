var Verifier = artifacts.require("VerifyPGHR13");

module.exports = function(deployer) {
	deployer.deploy(Verifier);
};