// SPDX-License-Identifier: LGPL-3.0+
const VERBOSE_LOG = false;

const fs = require('fs');
const Verifier = artifacts.require("VerifiyGroth16");

const homedir = (process.platform === 'win32') ? process.env.HOMEPATH : process.env.HOME;
const zktermVK      = homedir + '/zkconsent_setup/groth16/zkterm/vk_zkterm_params.json'
const zktermProof   = homedir + '/zkconsent_setup/groth16/zkterm/exproof_zkterm_params.json'
const zktermInputs  = homedir + '/zkconsent_setup/groth16/zkterm/exproof_zkterm.json'
const zktermProof2  = homedir + '/zkconsent_setup/groth16/other/zkterm/exproof_zkterm_params.json'
const zktermInputs2 = homedir + '/zkconsent_setup/groth16/other/zkterm/exproof_zkterm.json'

const zkmintVK       = homedir + '/zkconsent_setup/groth16/zkmint/vk_zkmint_params.json'
const zkmintProof    = homedir + '/zkconsent_setup/groth16/zkmint/exproof_zkmint_params.json'
const zkmintInputs   = homedir + '/zkconsent_setup/groth16/zkmint/exproof_zkmint.json'
const zkmintProof2   = homedir + '/zkconsent_setup/groth16/other/zkmint/exproof_zkmint_params.json'
const zkmintInputs2  = homedir + '/zkconsent_setup/groth16/other/zkmint/exproof_zkmint.json'

const zkconsVK      = homedir + '/zkconsent_setup/groth16/zkcons/vk_zkcons_params.json'
const zkconsProof   = homedir + '/zkconsent_setup/groth16/zkcons/exproof_zkcons_params.json'
const zkconsInputs  = homedir + '/zkconsent_setup/groth16/zkcons/exproof_zkcons.json'
const zkconsProof2  = homedir + '/zkconsent_setup/groth16/other/zkcons/exproof_zkcons_params.json'
const zkconsInputs2 = homedir + '/zkconsent_setup/groth16/other/zkcons/exproof_zkcons.json'

const zkconfconsVK      = homedir + '/zkconsent_setup/groth16/zkconfcons/vk_zkconfcons_params.json'
const zkconfconsProof   = homedir + '/zkconsent_setup/groth16/zkconfcons/exproof_zkconfcons_params.json'
const zkconfconsInputs  = homedir + '/zkconsent_setup/groth16/zkconfcons/exproof_zkconfcons.json'
const zkconfconsProof2  = homedir + '/zkconsent_setup/groth16/other/zkconfcons/exproof_zkconfcons_params.json'
const zkconfconsInputs2 = homedir + '/zkconsent_setup/groth16/other/zkconfcons/exproof_zkconfcons.json'

const zkconftermVK      = homedir + '/zkconsent_setup/groth16/zkconfterm/vk_zkconfterm_params.json'
const zkconftermProof   = homedir + '/zkconsent_setup/groth16/zkconfterm/exproof_zkconfterm_params.json'
const zkconftermInputs  = homedir + '/zkconsent_setup/groth16/zkconfterm/exproof_zkconfterm.json'
const zkconftermProof2  = homedir + '/zkconsent_setup/groth16/other/zkconfterm/exproof_zkconfterm_params.json'
const zkconftermInputs2 = homedir + '/zkconsent_setup/groth16/other/zkconfterm/exproof_zkconfterm.json'

const zksimptermVK      = homedir + '/zkconsent_setup/groth16/zksimpterm/vk_zksimpterm_params.json'
const zksimptermProof   = homedir + '/zkconsent_setup/groth16/zksimpterm/exproof_zksimpterm_params.json'
const zksimptermInputs  = homedir + '/zkconsent_setup/groth16/zksimpterm/exproof_zksimpterm.json'
const zksimptermProof2  = homedir + '/zkconsent_setup/groth16/other/zksimpterm/exproof_zksimpterm_params.json'
const zksimptermInputs2 = homedir + '/zkconsent_setup/groth16/other/zksimpterm/exproof_zksimpterm.json'

const zksimpmintVK       = homedir + '/zkconsent_setup/groth16/zksimpmint/vk_zksimpmint_params.json'
const zksimpmintProof    = homedir + '/zkconsent_setup/groth16/zksimpmint/exproof_zksimpmint_params.json'
const zksimpmintInputs   = homedir + '/zkconsent_setup/groth16/zksimpmint/exproof_zksimpmint.json'
const zksimpmintProof2   = homedir + '/zkconsent_setup/groth16/other/zksimpmint/exproof_zksimpmint_params.json'
const zksimpmintInputs2  = homedir + '/zkconsent_setup/groth16/other/zksimpmint/exproof_zksimpmint.json'

const zksimpconsVK      = homedir + '/zkconsent_setup/groth16/zksimpcons/vk_zksimpcons_params.json'
const zksimpconsProof   = homedir + '/zkconsent_setup/groth16/zksimpcons/exproof_zksimpcons_params.json'
const zksimpconsInputs  = homedir + '/zkconsent_setup/groth16/zksimpcons/exproof_zksimpcons.json'
const zksimpconsProof2  = homedir + '/zkconsent_setup/groth16/other/zksimpcons/exproof_zksimpcons_params.json'
const zksimpconsInputs2 = homedir + '/zkconsent_setup/groth16/other/zksimpcons/exproof_zksimpcons.json'


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

contract('zkConsent Groth16 Verification', function(accounts) 
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

	it("zkterm: should set verifying key",          async () => await setkeyTest(zktermVK));
	it("zkterm: should verify correct proof",       async () => await verifyOkTest(zktermVK, zktermProof, zktermInputs));
	it("zkterm: should verify correct proof2",      async () => await verifyOkTest(zktermVK, zktermProof2, zktermInputs2));
	it("zkterm: shouldn't verify incorrect proof",  async () => await verifyWrong(zktermVK, zktermProof2, zktermInputs));
	it("zkterm: shouldn't verify incorrect input",  async () => await verifyWrong(zktermVK, zktermProof, zktermInputs2));

	it("zkmint: should set verifying key",          async () => await setkeyTest(zkmintVK));
	it("zkmint: should verify correct proof",       async () => await verifyOkTest(zkmintVK, zkmintProof, zkmintInputs));
	it("zkmint: should verify correct proof2",      async () => await verifyOkTest(zkmintVK, zkmintProof2, zkmintInputs2));
	it("zkmint: shouldn't verify incorrect proof",  async () => await verifyWrong(zkmintVK, zkmintProof2, zkmintInputs));
	it("zkmint: shouldn't verify incorrect input",  async () => await verifyWrong(zkmintVK, zkmintProof, zkmintInputs2));

    it("zkcons: should set verifying key",          async () => await setkeyTest(zkconsVK));
	it("zkcons: should verify correct proof",       async () => await verifyOkTest(zkconsVK, zkconsProof, zkconsInputs));
	it("zkcons: should verify correct proof2",      async () => await verifyOkTest(zkconsVK, zkconsProof2, zkconsInputs2));
	it("zkcons: shouldn't verify incorrect proof",  async () => await verifyWrong(zkconsVK, zkconsProof2, zkconsInputs));
	it("zkcons: shouldn't verify incorrect input",  async () => await verifyWrong(zkconsVK, zkconsProof, zkconsInputs2));

    it("zkconfcons: should set verifying key",          async () => await setkeyTest(zkconfconsVK));
	it("zkconfcons: should verify correct proof",       async () => await verifyOkTest(zkconfconsVK, zkconfconsProof, zkconfconsInputs));
	it("zkconfcons: should verify correct proof2",      async () => await verifyOkTest(zkconfconsVK, zkconfconsProof2, zkconfconsInputs2));
	it("zkconfcons: shouldn't verify incorrect proof",  async () => await verifyWrong(zkconfconsVK, zkconfconsProof2, zkconfconsInputs));
	it("zkconfcons: shouldn't verify incorrect input",  async () => await verifyWrong(zkconfconsVK, zkconfconsProof, zkconfconsInputs2));

    it("zkconfterm: should set verifying key",          async () => await setkeyTest(zkconftermVK));
	it("zkconfterm: should verify correct proof",       async () => await verifyOkTest(zkconftermVK, zkconftermProof, zkconftermInputs));
	it("zkconfterm: should verify correct proof2",      async () => await verifyOkTest(zkconftermVK, zkconftermProof2, zkconftermInputs2));
	it("zkconfterm: shouldn't verify incorrect proof",  async () => await verifyWrong(zkconftermVK, zkconftermProof2, zkconftermInputs));
	it("zkconfterm: shouldn't verify incorrect input",  async () => await verifyWrong(zkconftermVK, zkconftermProof, zkconftermInputs2));

	it("zksimpterm: should set verifying key",          async () => await setkeyTest(zksimptermVK));
	it("zksimpterm: should verify correct proof",       async () => await verifyOkTest(zksimptermVK, zksimptermProof, zksimptermInputs));
	it("zksimpterm: should verify correct proof2",      async () => await verifyOkTest(zksimptermVK, zksimptermProof2, zksimptermInputs2));
	it("zksimpterm: shouldn't verify incorrect proof",  async () => await verifyWrong(zksimptermVK, zksimptermProof2, zksimptermInputs));
	it("zksimpterm: shouldn't verify incorrect input",  async () => await verifyWrong(zksimptermVK, zksimptermProof, zksimptermInputs2));

	it("zksimpmint: should set verifying key",          async () => await setkeyTest(zksimpmintVK));
	it("zksimpmint: should verify correct proof",       async () => await verifyOkTest(zksimpmintVK, zksimpmintProof, zksimpmintInputs));
	it("zksimpmint: should verify correct proof2",      async () => await verifyOkTest(zksimpmintVK, zksimpmintProof2, zksimpmintInputs2));
	it("zksimpmint: shouldn't verify incorrect proof",  async () => await verifyWrong(zksimpmintVK, zksimpmintProof2, zksimpmintInputs));
	it("zksimpmint: shouldn't verify incorrect input",  async () => await verifyWrong(zksimpmintVK, zksimpmintProof, zksimpmintInputs2));

    it("zksimpcons: should set verifying key",          async () => await setkeyTest(zksimpconsVK));
	it("zksimpcons: should verify correct proof",       async () => await verifyOkTest(zksimpconsVK, zksimpconsProof, zksimpconsInputs));
	it("zksimpcons: should verify correct proof2",      async () => await verifyOkTest(zksimpconsVK, zksimpconsProof2, zksimpconsInputs2));
	it("zksimpcons: shouldn't verify incorrect proof",  async () => await verifyWrong(zksimpconsVK, zksimpconsProof2, zksimpconsInputs));
	it("zksimpcons: shouldn't verify incorrect input",  async () => await verifyWrong(zksimpconsVK, zksimpconsProof, zksimpconsInputs2));
});
