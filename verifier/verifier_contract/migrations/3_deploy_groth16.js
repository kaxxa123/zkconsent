var Verifier = artifacts.require("VerifiyGroth16");

module.exports = function(deployer) {
	deployer.deploy(Verifier);
};