// SPDX-License-Identifier: LGPL-3.0+
const VERBOSE_LOG = false;

const fs = require('fs');
const Verifier = artifacts.require("VerifyPGHR13");

const homedir = (process.platform === 'win32') ? process.env.HOMEPATH : process.env.HOME;
const zktermVK     = homedir + '/zkconsent_setup/pghr13/zkterm/vk_zkterm.json'
const zktermProof  = homedir + '/zkconsent_setup/pghr13/zkterm/exproof_zkterm.json'
const zktermProof2 = homedir + '/zkconsent_setup/pghr13/other/zkterm/exproof_zkterm.json'

const zkmintVK     = homedir + '/zkconsent_setup/pghr13/zkmint/vk_zkmint.json'
const zkmintProof  = homedir + '/zkconsent_setup/pghr13/zkmint/exproof_zkmint.json'
const zkmintProof2 = homedir + '/zkconsent_setup/pghr13/other/zkmint/exproof_zkmint.json'

const zkconsVK     = homedir + '/zkconsent_setup/pghr13/zkcons/vk_zkcons.json'
const zkconsProof  = homedir + '/zkconsent_setup/pghr13/zkcons/exproof_zkcons.json'
const zkconsProof2 = homedir + '/zkconsent_setup/pghr13/other/zkcons/exproof_zkcons.json'

const zkconfconsVK     = homedir + '/zkconsent_setup/pghr13/zkconfcons/vk_zkconfcons.json'
const zkconfconsProof  = homedir + '/zkconsent_setup/pghr13/zkconfcons/exproof_zkconfcons.json'
const zkconfconsProof2 = homedir + '/zkconsent_setup/pghr13/other/zkconfcons/exproof_zkconfcons.json'

const zkconftermVK     = homedir + '/zkconsent_setup/pghr13/zkconfterm/vk_zkconfterm.json'
const zkconftermProof  = homedir + '/zkconsent_setup/pghr13/zkconfterm/exproof_zkconfterm.json'
const zkconftermProof2 = homedir + '/zkconsent_setup/pghr13/other/zkconfterm/exproof_zkconfterm.json'

const zksimptermVK     = homedir + '/zkconsent_setup/pghr13/zksimpterm/vk_zksimpterm.json'
const zksimptermProof  = homedir + '/zkconsent_setup/pghr13/zksimpterm/exproof_zksimpterm.json'
const zksimptermProof2 = homedir + '/zkconsent_setup/pghr13/other/zksimpterm/exproof_zksimpterm.json'

const zksimpmintVK     = homedir + '/zkconsent_setup/pghr13/zksimpmint/vk_zksimpmint.json'
const zksimpmintProof  = homedir + '/zkconsent_setup/pghr13/zksimpmint/exproof_zksimpmint.json'
const zksimpmintProof2 = homedir + '/zkconsent_setup/pghr13/other/zksimpmint/exproof_zksimpmint.json'

const zksimpconsVK     = homedir + '/zkconsent_setup/pghr13/zksimpcons/vk_zksimpcons.json'
const zksimpconsProof  = homedir + '/zkconsent_setup/pghr13/zksimpcons/exproof_zksimpcons.json'
const zksimpconsProof2 = homedir + '/zkconsent_setup/pghr13/other/zksimpcons/exproof_zksimpcons.json'


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

const parseG1Point = (pt) => {
    var X = hexToDec(pt[0]);
    var Y = hexToDec(pt[1]);
    return [X, Y];
}

const parseG2Point = (pt) => {
    var X = [hexToDec(pt[0][1]), hexToDec(pt[0][0])];
    var Y = [hexToDec(pt[1][1]), hexToDec(pt[1][0])];
    return [X, Y];
}

const loadVK = (jsonFile) => {
    let jvk = loadJSON(jsonFile)
    
    let A = parseG2Point(jvk.a);
    let B = parseG1Point(jvk.b);
    let C = parseG2Point(jvk.c);
    let gamma = parseG2Point(jvk.g);
    let gamma_beta_1 = parseG1Point(jvk.gb1);
    let gamma_beta_2 = parseG2Point(jvk.gb2);
    let Z = parseG2Point(jvk.z);

    let IC = [];
    jvk.IC.forEach( pt => IC.push(parseG1Point(pt)));

    return {A, B, C, gamma, gamma_beta_1, gamma_beta_2, Z, IC}
}

const loadProof = (jsonFile) => {
    let proof = loadJSON(jsonFile)

    A_g = parseG1Point(proof.proof.a);
    A_h = parseG1Point(proof.proof.a_p);
    B_g = parseG2Point(proof.proof.b);
    B_h = parseG1Point(proof.proof.b_p);
    C_g = parseG1Point(proof.proof.c);
    C_h = parseG1Point(proof.proof.c_p);
    H = parseG1Point(proof.proof.h);
    K = parseG1Point(proof.proof.k);

    return {A_g, A_h, B_g, B_h, C_g, C_h, H, K};
}

const loadInput = (jsonFile) => {
    let proof = loadJSON(jsonFile)
    
    let pubInput = [];
    proof.inputs.forEach( val => pubInput.push(hexToDec(val)));
    return pubInput;
}

const VerboseLog = (str) => {
    if (VERBOSE_LOG)
        console.log(str);
}

contract('zkConsent PGHR13 Verification', function(accounts) 
{
    const setkeyTest = async (jsonVK) => {
        assert (fs.existsSync(jsonVK), `File not found: ${jsonVK}`);

		verifier = await Verifier.new();
		
        VerboseLog("Loading VK...")
        let vk = loadVK(jsonVK)

        VerboseLog("Setting VK at verifier...")
		await verifier.setVerifyingKey(vk.A, vk.B, vk.C, vk.gamma, vk.gamma_beta_1, vk.gamma_beta_2, vk.Z, vk.IC);

        let vkSet = await verifier.verifyingKeySet();
        assert(vkSet, "Verification key not set")
    }

    const verifyOkTest = async (jsonVK, jsonProof, jsonInputs) => {
        assert (fs.existsSync(jsonVK), `File not found: ${jsonVK}`);
        assert (fs.existsSync(jsonProof), `File not found: ${jsonProof}`);
        assert (fs.existsSync(jsonInputs), `File not found: ${jsonInputs}`);

        VerboseLog("Loading Proof...")
        let pi = loadProof(jsonProof)

        VerboseLog("Loading Public Input...")
        let pubIn = loadInput(jsonInputs)

        let gasEst = await verifier.verifyTx.estimateGas(pi.A_g, pi.A_h, pi.B_g, pi.B_h, pi.C_g, pi.C_h,
                                                            pi.H, pi.K, pubIn);
        console.log(`GAS: verifyTx: ${gasEst}`);

        VerboseLog("Verifing...")
        let res = await verifier.verifyTx.call(pi.A_g, pi.A_h, pi.B_g, pi.B_h, pi.C_g, pi.C_h,
                                                pi.H, pi.K, pubIn);

        assert(res,"ERROR: Correct Proof NOT Verified!")
    }

    const verifyWrong = async (jsonVK, jsonProof, jsonInputs) => {
        assert (fs.existsSync(jsonVK), `File not found: ${jsonVK}`);
        assert (fs.existsSync(jsonProof), `File not found: ${jsonProof}`);
        assert (fs.existsSync(jsonInputs), `File not found: ${jsonInputs}`);

        if (!fs.existsSync(jsonVK) || !fs.existsSync(jsonProof) || !fs.existsSync(jsonInputs))
            return;

        VerboseLog("Loading Proof...")
        let pi = loadProof(jsonProof)

        VerboseLog("Loading Public Input...")
        let pubIn = loadInput(jsonInputs)
    
        VerboseLog("Verifiying Incorrect Proof/Input...")
        let res = await verifier.verifyTx.call(pi.A_g, pi.A_h, pi.B_g, pi.B_h, pi.C_g, pi.C_h,
            pi.H, pi.K, pubIn);

        assert(!res,"ERROR: Incorrect Proof/Input Verified!")
    }

	it("zkterm: should set verifying key",          async () => await setkeyTest(zktermVK));
	it("zkterm: should verify correct proof",       async () => await verifyOkTest(zktermVK, zktermProof, zktermProof));
	it("zkterm: should verify correct proof2",      async () => await verifyOkTest(zktermVK, zktermProof2, zktermProof2));
	it("zkterm: shouldn't verify incorrect proof",  async () => await verifyWrong(zktermVK, zktermProof2, zktermProof));
	it("zkterm: shouldn't verify incorrect input",  async () => await verifyWrong(zktermVK, zktermProof, zktermProof2));

    it("zkmint: should set verifying key",          async () => await setkeyTest(zkmintVK));
	it("zkmint: should verify correct proof",       async () => await verifyOkTest(zkmintVK, zkmintProof, zkmintProof));
	it("zkmint: should verify correct proof2",      async () => await verifyOkTest(zkmintVK, zkmintProof2, zkmintProof2));
	it("zkmint: shouldn't verify incorrect proof",  async () => await verifyWrong(zkmintVK, zkmintProof2, zkmintProof));
	it("zkmint: shouldn't verify incorrect input",  async () => await verifyWrong(zkmintVK, zkmintProof, zkmintProof2));

    it("zkcons: should set verifying key",          async () => await setkeyTest(zkconsVK));
	it("zkcons: should verify correct proof",       async () => await verifyOkTest(zkconsVK, zkconsProof, zkconsProof));
	it("zkcons: should verify correct proof2",      async () => await verifyOkTest(zkconsVK, zkconsProof2, zkconsProof2));
	it("zkcons: shouldn't verify incorrect proof",  async () => await verifyWrong(zkconsVK, zkconsProof2, zkconsProof));
	it("zkcons: shouldn't verify incorrect input",  async () => await verifyWrong(zkconsVK, zkconsProof, zkconsProof2));

    it("zkconfcons: should set verifying key",          async () => await setkeyTest(zkconfconsVK));
	it("zkconfcons: should verify correct proof",       async () => await verifyOkTest(zkconfconsVK, zkconfconsProof, zkconfconsProof));
	it("zkconfcons: should verify correct proof2",      async () => await verifyOkTest(zkconfconsVK, zkconfconsProof2, zkconfconsProof2));
	it("zkconfcons: shouldn't verify incorrect proof",  async () => await verifyWrong(zkconfconsVK, zkconfconsProof2, zkconfconsProof));
	it("zkconfcons: shouldn't verify incorrect input",  async () => await verifyWrong(zkconfconsVK, zkconfconsProof, zkconfconsProof2));
    
    it("zkconfterm: should set verifying key",          async () => await setkeyTest(zkconftermVK));
	it("zkconfterm: should verify correct proof",       async () => await verifyOkTest(zkconftermVK, zkconftermProof, zkconftermProof));
	it("zkconfterm: should verify correct proof2",      async () => await verifyOkTest(zkconftermVK, zkconftermProof2, zkconftermProof2));
	it("zkconfterm: shouldn't verify incorrect proof",  async () => await verifyWrong(zkconftermVK, zkconftermProof2, zkconftermProof));
	it("zkconfterm: shouldn't verify incorrect input",  async () => await verifyWrong(zkconftermVK, zkconftermProof, zkconftermProof2));

	it("zksimpterm: should set verifying key",          async () => await setkeyTest(zksimptermVK));
	it("zksimpterm: should verify correct proof",       async () => await verifyOkTest(zksimptermVK, zksimptermProof, zksimptermProof));
	it("zksimpterm: should verify correct proof2",      async () => await verifyOkTest(zksimptermVK, zksimptermProof2, zksimptermProof2));
	it("zksimpterm: shouldn't verify incorrect proof",  async () => await verifyWrong(zksimptermVK, zksimptermProof2, zksimptermProof));
	it("zksimpterm: shouldn't verify incorrect input",  async () => await verifyWrong(zksimptermVK, zksimptermProof, zksimptermProof2));

    it("zksimpmint: should set verifying key",          async () => await setkeyTest(zksimpmintVK));
	it("zksimpmint: should verify correct proof",       async () => await verifyOkTest(zksimpmintVK, zksimpmintProof, zksimpmintProof));
	it("zksimpmint: should verify correct proof2",      async () => await verifyOkTest(zksimpmintVK, zksimpmintProof2, zksimpmintProof2));
	it("zksimpmint: shouldn't verify incorrect proof",  async () => await verifyWrong(zksimpmintVK, zksimpmintProof2, zksimpmintProof));
	it("zksimpmint: shouldn't verify incorrect input",  async () => await verifyWrong(zksimpmintVK, zksimpmintProof, zksimpmintProof2));

    it("zksimpcons: should set verifying key",          async () => await setkeyTest(zksimpconsVK));
	it("zksimpcons: should verify correct proof",       async () => await verifyOkTest(zksimpconsVK, zksimpconsProof, zksimpconsProof));
	it("zksimpcons: should verify correct proof2",      async () => await verifyOkTest(zksimpconsVK, zksimpconsProof2, zksimpconsProof2));
	it("zksimpcons: shouldn't verify incorrect proof",  async () => await verifyWrong(zksimpconsVK, zksimpconsProof2, zksimpconsProof));
	it("zksimpcons: shouldn't verify incorrect input",  async () => await verifyWrong(zksimpconsVK, zksimpconsProof, zksimpconsProof2));
});

// console.log(pubIn)

// console.log(A)
// console.log(B)
// console.log(C)
// console.log(gamma)
// console.log(gamma_beta_1)
// console.log(gamma_beta_2)
// console.log(Z)
// console.log(IC)

// console.log(A_g)
// console.log(A_h)
// console.log(B_g)
// console.log(B_h)
// console.log(C_g)
// console.log(C_h)
// console.log(H)
// console.log(K)

