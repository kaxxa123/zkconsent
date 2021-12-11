// SPDX-License-Identifier: LGPL-3.0+
const VERBOSE_LOG = false;

const fs = require('fs');
const Verifier = artifacts.require("VerifiyGroth16");

const homedir = (process.platform === 'win32') ? process.env.HOMEPATH : process.env.HOME;
const zkVK           = homedir + '/zkconsent/zeth_tests/vk/vk_zeth_params.json'

const zkmintProof    = homedir + '/zkconsent/zeth_tests/proofs/exproof_mint_params.json'
const zkmintInputs   = homedir + '/zkconsent/zeth_tests/proofs/exproof_mint.json'
const zkmintProof2   = homedir + '/zkconsent/zeth_tests/proofs/exproof_mint2_params.json'
const zkmintInputs2  = homedir + '/zkconsent/zeth_tests/proofs/exproof_mint2.json'

const zktxProof      = homedir + '/zkconsent/zeth_tests/proofs/exproof_tx_params.json'
const zktxInputs     = homedir + '/zkconsent/zeth_tests/proofs/exproof_tx.json'
const zktxProof2     = homedir + '/zkconsent/zeth_tests/proofs/exproof_tx2_params.json'
const zktxInputs2    = homedir + '/zkconsent/zeth_tests/proofs/exproof_tx2.json'

const zkburnProof    = homedir + '/zkconsent/zeth_tests/proofs/exproof_burn_params.json'
const zkburnInputs   = homedir + '/zkconsent/zeth_tests/proofs/exproof_burn.json'
const zkburnProof2   = homedir + '/zkconsent/zeth_tests/proofs/exproof_burn2_params.json'
const zkburnInputs2  = homedir + '/zkconsent/zeth_tests/proofs/exproof_burn2.json'

var verifier; 

//https://stackoverflow.com/questions/21667377/javascript-hexadecimal-string-to-decimal-string
const hexToDec = (s) => {
    if (s.startsWith('0x') || s.startsWith('0X'))
        s = s.slice(2)

    var i, j, digits = [0], carry;
    for (i = 0; i < s.length; i += 1) {
        carry = parseInt(s.charAt(i), 16);
        for (j = 0; j < digits.length; j += 1) {
            digits[j] = digits[j] * 16 + carry;
            carry = digits[j] / 10 | 0;
            digits[j] %= 10;
        }
        while (carry > 0) {
            digits.push(carry % 10);
            carry = carry / 10 | 0;
        }
    }
    return digits.reverse().join('');
}

const loadJSON = (jsonFile) => {
    try
    {    
        const dataBuffer = fs.readFileSync(jsonFile)
        const dataJSON = dataBuffer.toString()

        return JSON.parse(dataJSON)
    }
    catch   (e)
    {
        return [];
    }
}

const loadVK = (jsonFile) => {
    let vk = loadJSON(jsonFile)
    let vkInput    = [];
    vk.forEach(val => vkInput.push(hexToDec(val)));
    return vkInput;
 }

 const loadProof = (jsonFile) => {
    let proof = loadJSON(jsonFile)
    let proofInput = [];
    proof.forEach(val => proofInput.push(hexToDec(val)));
    return proofInput;
}

const loadInput = (jsonFile) => {
    let proof = loadJSON(jsonFile)
    let pubInput = [];
    proof.inputs.forEach(val => pubInput.push(hexToDec(val)));
    return pubInput;
}

const VerboseLog = (str) => {
    if (VERBOSE_LOG)
        console.log(str);
}

contract('Zeth Groth16 Verification', function(accounts) 
{
    const setkeyTest = async (jsonVK) => {
        assert (fs.existsSync(jsonVK), `File not found: ${jsonVK}`);

		verifier = await Verifier.new();
		
        VerboseLog("Loading VK...")
        let vkIn = loadVK(jsonVK)

        VerboseLog("Setting VK at verifier...")
		await verifier.setVerifyingKey(vkIn);

        let vkSet = await verifier.verifyingKeySet();
        assert(vkSet, "Verification key not set")
    }

    const verifyOkTest = async (jsonVK, jsonProof, jsonInputs) => {
        assert (fs.existsSync(jsonVK), `File not found: ${jsonVK}`);
        assert (fs.existsSync(jsonProof), `File not found: ${jsonProof}`);
        assert (fs.existsSync(jsonInputs), `File not found: ${jsonInputs}`);

        VerboseLog("Loading Proof...")
        let proofIn = loadProof(jsonProof)

        VerboseLog("Loading Public Input...")
        let pubIn = loadInput(jsonInputs)

        let gasEst = await verifier.verifyTx.estimateGas(proofIn, pubIn);
        console.log(`GAS: verifyTx: ${gasEst}`);

        VerboseLog("Verifing...")
        let res = await verifier.verifyTx.call(proofIn, pubIn);

        assert(res,"ERROR: Correct Proof NOT Verified!")
    }

    const verifyWrong = async (jsonVK, jsonProof, jsonInputs) => {
        assert (fs.existsSync(jsonVK), `File not found: ${jsonVK}`);
        assert (fs.existsSync(jsonProof), `File not found: ${jsonProof}`);
        assert (fs.existsSync(jsonInputs), `File not found: ${jsonInputs}`);

        VerboseLog("Loading Proof...")
        let proofIn = loadProof(jsonProof)
    
        VerboseLog("Loading Public Input...")
        let pubIn = loadInput(jsonInputs)

        VerboseLog("Verifiying Incorrect Proof/Input...")
        let res = await verifier.verifyTx.call(proofIn, pubIn);
        assert(!res,"ERROR: Incorrect Proof/Input Verified!")
    }    

	it("zkmint: should set verifying key",          async () => await setkeyTest(zkVK));
    
	it("zkmint: should verify correct proof",       async () => await verifyOkTest(zkVK, zkmintProof, zkmintInputs));
    it("zkmint: should verify correct proof2",      async () => await verifyOkTest(zkVK, zkmintProof2, zkmintInputs2));
	it("zkmint: shouldn't verify incorrect proof",  async () => await verifyWrong(zkVK, zkmintProof2, zkmintInputs));
	it("zkmint: shouldn't verify incorrect input",  async () => await verifyWrong(zkVK, zkmintProof, zkmintInputs2));

	it("zkTX: should verify correct proof",         async () => await verifyOkTest(zkVK, zktxProof, zktxInputs));
    it("zkTX: should verify correct proof2",        async () => await verifyOkTest(zkVK, zktxProof2, zktxInputs2));
	it("zkTX: shouldn't verify incorrect proof",    async () => await verifyWrong(zkVK, zktxProof2, zktxInputs));
	it("zkTX: shouldn't verify incorrect input",    async () => await verifyWrong(zkVK, zktxProof, zktxInputs2));

    it("zkburn: should verify correct proof",       async () => await verifyOkTest(zkVK, zkburnProof, zkburnInputs));
    it("zkburn: should verify correct proof2",      async () => await verifyOkTest(zkVK, zkburnProof2, zkburnInputs2));
	it("zkburn: shouldn't verify incorrect proof",  async () => await verifyWrong(zkVK, zkburnProof2, zkburnInputs));
	it("zkburn: shouldn't verify incorrect input",  async () => await verifyWrong(zkVK, zkburnProof, zkburnInputs2));
});
