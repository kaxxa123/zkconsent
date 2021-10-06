// SPDX-License-Identifier: LGPL-3.0+

const fs = require('fs');
const Verifier = artifacts.require("VerifiyGroth16");

const homedir = (process.platform === 'win32') ? process.env.HOMEPATH : process.env.HOME;
const zktermVK      = homedir + '/zkconsent_setup/groth16/zkterm/vk_zkterm_params.json'
const zktermProof   = homedir + '/zkconsent_setup/groth16/zkterm/exproof_zkterm_params.json'
const zktermInputs  = homedir + '/zkconsent_setup/groth16/zkterm/exproof_zkterm.json'

const zkmintVK      = homedir + '/zkconsent_setup/groth16/zkmint/vk_zkmint_params.json'
const zkmintProof   = homedir + '/zkconsent_setup/groth16/zkmint/exproof_zkmint_params.json'
const zkmintInputs  = homedir + '/zkconsent_setup/groth16/zkmint/exproof_zkmint.json'

const zkconsVK      = homedir + '/zkconsent_setup/groth16/zkcons/vk_zkcons_params.json'
const zkconsProof   = homedir + '/zkconsent_setup/groth16/zkcons/exproof_zkcons_params.json'
const zkconsInputs  = homedir + '/zkconsent_setup/groth16/zkcons/exproof_zkcons.json'

const zkconfVK      = homedir + '/zkconsent_setup/groth16/zkconf/vk_zkconf_params.json'
const zkconfProof   = homedir + '/zkconsent_setup/groth16/zkconf/exproof_zkconf_params.json'
const zkconfInputs  = homedir + '/zkconsent_setup/groth16/zkconf/exproof_zkconf.json'

var vkIn    = [];
var proofIn = [];
var pubIn   = [];
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
    vkIn    = [];
    vk.forEach(val => vkIn.push(hexToDec(val)));
 }

 const loadProof = (jsonFile) => {
    let proof = loadJSON(jsonFile)
    proofIn = [];
    proof.forEach(val => proofIn.push(hexToDec(val)));
}

const loadInput = (jsonFile) => {
    let proof = loadJSON(jsonFile)
    
    pubIn = [];
    proof.inputs.forEach(val => pubIn.push(hexToDec(val)));
}

contract('Verifier', function(accounts) 
{
    const failOrFalse = async (name, lambda) => {
        let isTrue = true;
        try {
            isTrue = await lambda();
        }
        catch(err) {
            console.log(`OK: ${name} Failed!`)
            return;
        }

        if (isTrue)
            assert(false, `${name} should have returned False!`)

        console.log(`OK: ${name} returned False!`)
        return;
    }
    
    const setkeyTest = async (jsonVK, jsonProof, jsonInputs) => {
        if (!fs.existsSync(jsonVK))        console.log(`Skipping - File not found: ${jsonVK}`)
        if (!fs.existsSync(jsonProof))     console.log(`Skipping - File not found: ${jsonProof}`)
        if (!fs.existsSync(jsonInputs))    console.log(`Skipping - File not found: ${jsonInputs}`)

        if (!fs.existsSync(jsonVK) || !fs.existsSync(jsonProof) || !fs.existsSync(jsonInputs))
            return;

		verifier = await Verifier.new();
		
        console.log("Loading VK...")
        loadVK(jsonVK)

        console.log("Setting VK at verifier...")
		await verifier.setVerifyingKey(vkIn);

        let vkSet = await verifier.verifyingKeySet();
        assert(vkSet, "Verification key not set")
    }

    const verifyOkTest = async (jsonVK, jsonProof, jsonInputs) => {
        if (!fs.existsSync(jsonVK) || !fs.existsSync(jsonProof) || !fs.existsSync(jsonInputs))
            return;

        console.log("Loading Proof...")
        loadProof(jsonProof)

        console.log("Loading Public Input...")
        loadInput(jsonInputs)

        console.log("Verifing...")
        let res = await verifier.verifyTx.call(proofIn, pubIn);

        assert(res, "Correct Proof verified OK")
    }

    const verifyWrongProof = async (jsonVK, jsonProof, jsonInputs) => {
        if (!fs.existsSync(jsonVK) || !fs.existsSync(jsonProof) || !fs.existsSync(jsonInputs))
            return;

        console.log("Verifiying Incorrect Proof...")
        var wrongIn = [...proofIn];
        wrongIn[0] = wrongIn[2]
        wrongIn[1] = wrongIn[3]

        await failOrFalse("verifyTx(wrongProof)", () => verifier.verifyTx.call(wrongIn, pubIn))
    }

    const verifyWrongInput = async (jsonVK, jsonProof, jsonInputs) => {
        if (!fs.existsSync(jsonVK) || !fs.existsSync(jsonProof) || !fs.existsSync(jsonInputs))
            return;

        console.log("Verifiying Incorrect Input...")
        var wrongInput = [...pubIn];
        if (wrongInput[0] != 0)
                wrongInput[0] = 0;
        else    wrongInput[0] = 1;

        await failOrFalse("verifyTx(wrongInput)", () => verifier.verifyTx.call(proofIn, wrongInput))
    }    

	it("zkterm: should set verifying key",          async () => await setkeyTest(zktermVK, zktermProof, zktermInputs));
	it("zkterm: should verify correct proof",       async () => await verifyOkTest(zktermVK, zktermProof, zktermInputs));
	it("zkterm: shouldn't verify incorrect proof",  async () => await verifyWrongProof(zktermVK, zktermProof, zktermInputs));
	it("zkterm: shouldn't verify incorrect input",  async () => await verifyWrongInput(zktermVK, zktermProof, zktermInputs));

	it("zkmint: should set verifying key",          async () => await setkeyTest(zkmintVK, zkmintProof, zkmintInputs));
	it("zkmint: should verify correct proof",       async () => await verifyOkTest(zkmintVK, zkmintProof, zkmintInputs));
	it("zkmint: shouldn't verify incorrect proof",  async () => await verifyWrongProof(zkmintVK, zkmintProof, zkmintInputs));
	it("zkmint: shouldn't verify incorrect input",  async () => await verifyWrongInput(zkmintVK, zkmintProof, zkmintInputs));

    it("zkcons: should set verifying key",          async () => await setkeyTest(zkconsVK, zkconsProof, zkconsInputs));
	it("zkcons: should verify correct proof",       async () => await verifyOkTest(zkconsVK, zkconsProof, zkconsInputs));
	it("zkcons: shouldn't verify incorrect proof",  async () => await verifyWrongProof(zkconsVK, zkconsProof, zkconsInputs));
	it("zkcons: shouldn't verify incorrect input",  async () => await verifyWrongInput(zkconsVK, zkconsProof, zkconsInputs));

    it("zkconf: should set verifying key",          async () => await setkeyTest(zkconfVK, zkconfProof, zkconfInputs));
	it("zkconf: should verify correct proof",       async () => await verifyOkTest(zkconfVK, zkconfProof, zkconfInputs));
	it("zkconf: shouldn't verify incorrect proof",  async () => await verifyWrongProof(zkconfVK, zkconfProof, zkconfInputs));
	it("zkconf: shouldn't verify incorrect input",  async () => await verifyWrongInput(zkconfVK, zkconfProof, zkconfInputs));
});
