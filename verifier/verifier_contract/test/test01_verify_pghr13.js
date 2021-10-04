// SPDX-License-Identifier: LGPL-3.0+

const fs = require('fs');
const Verifier = artifacts.require("VerifyPGHR13");

const homedir = (process.platform === 'win32') ? process.env.HOMEPATH : process.env.HOME;
const zktermVK    = homedir + '/zkconsent_setup/pghr13/zkterm/vk_zkterm.json'
const zktermProof = homedir + '/zkconsent_setup/pghr13/zkterm/exproof_zkterm.json'
const zkmintVK    = homedir + '/zkconsent_setup/pghr13/zkmint/vk_zkmint.json'
const zkmintProof = homedir + '/zkconsent_setup/pghr13/zkmint/exproof_zkmint.json'
const zkconsVK    = homedir + '/zkconsent_setup/pghr13/zkcons/vk_zkcons.json'
const zkconsProof = homedir + '/zkconsent_setup/pghr13/zkcons/exproof_zkcons.json'
const zkconfVK    = homedir + '/zkconsent_setup/pghr13/zkconf/vk_zkconf.json'
const zkconfProof = homedir + '/zkconsent_setup/pghr13/zkconf/exproof_zkconf.json'

//VK======================
var A, B, C;
var gamma, gamma_beta_1, gamma_beta_2;
var Z;
var IC = [];

//Proof===================
var A_g, A_h, B_g, B_h, C_g, C_h;
var H, K;

//Public Input============
var pubIn = [];

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
    let vk = loadJSON(jsonFile)
    
    A = parseG2Point(vk.a);
    B = parseG1Point(vk.b);
    C = parseG2Point(vk.c);
    gamma = parseG2Point(vk.g);
    gamma_beta_1 = parseG1Point(vk.gb1);
    gamma_beta_2 = parseG2Point(vk.gb2);
    Z = parseG2Point(vk.z);

    IC = [];
    vk.IC.forEach( pt => IC.push(parseG1Point(pt)));
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
}

const loadInput = (jsonFile) => {
    let proof = loadJSON(jsonFile)
    
    pubIn = [];
    proof.inputs.forEach( val => pubIn.push(hexToDec(val)));
}

contract('Verifier', function(accounts) 
{
    const setkeyTest = async (jsonVK, jsonProof) => {
        if (!fs.existsSync(jsonVK))        console.log(`Skipping - File not found: ${jsonVK}`)
        if (!fs.existsSync(jsonProof))     console.log(`Skipping - File not found: ${jsonProof}`)

        if (!fs.existsSync(jsonVK) || !fs.existsSync(jsonProof))
            return;

		verifier = await Verifier.new();
		
        console.log("Loading VK...")
        loadVK(jsonVK)

        console.log("Setting VK at verifier...")
		await verifier.setVerifyingKey(A, B, C, gamma, gamma_beta_1, gamma_beta_2, Z,IC);

        let vkSet = await verifier.verifyingKeySet();
        assert(vkSet, "Verification key not set")
    }

    const verifyOkTest = async (jsonVK, jsonProof) => {
        if (!fs.existsSync(jsonVK) || !fs.existsSync(jsonProof))
            return;

        console.log("Loading Proof...")
        loadProof(jsonProof)

        console.log("Loading Public Input...")
        loadInput(jsonProof)

        console.log("Verifing...")
        let res = await verifier.verifyTx.call(A_g, A_h, B_g, B_h, C_g, C_h,
                                        H, K, pubIn);

        assert(res, "Correct Proof verified OK")
    }

    const verifyWrongProof = async (jsonVK, jsonProof) => {
        if (!fs.existsSync(jsonVK) || !fs.existsSync(jsonProof))
            return;

        console.log("Verifiying Incorrect Proof...")
        var wrongA_g = [...A_h];
        let res = await verifier.verifyTx.call(wrongA_g, A_h, B_g, B_h, C_g, C_h,
                                        H, K, pubIn);
        assert(!res, "Incorrect Proof Not verified OK")
    }

    const verifyWrongInput = async (jsonVK, jsonProof) => {
        if (!fs.existsSync(jsonVK) || !fs.existsSync(jsonProof))
            return;

        console.log("Verifiying Incorrect Input...")
        var wrongInput = [...pubIn];
        if (wrongInput[0] != 0)
                wrongInput[0] = 0;
        else    wrongInput[0] = 1;
        let res = await verifier.verifyTx.call(A_g, A_h, B_g, B_h, C_g, C_h,
                                        H, K, wrongInput);
        assert(!res, "Incorrect Input Not verified OK")
    }    

	it("zkterm: should set verifying key",          async () => await setkeyTest(zktermVK, zktermProof));
	it("zkterm: should verify correct proof",       async () => await verifyOkTest(zktermVK, zktermProof));
	it("zkterm: shouldn't verify incorrect proof",  async () => await verifyWrongProof(zktermVK, zktermProof));
	it("zkterm: shouldn't verify incorrect input",  async () => await verifyWrongInput(zktermVK, zktermProof));

	it("zkmint: should set verifying key",          async () => await setkeyTest(zkmintVK, zkmintProof));
	it("zkmint: should verify correct proof",       async () => await verifyOkTest(zkmintVK, zkmintProof));
	it("zkmint: shouldn't verify incorrect proof",  async () => await verifyWrongProof(zkmintVK, zkmintProof));
	it("zkmint: shouldn't verify incorrect input",  async () => await verifyWrongInput(zkmintVK, zkmintProof));

	it("zkcons: should set verifying key",          async () => await setkeyTest(zkconsVK, zkconsProof));
	it("zkcons: should verify correct proof",       async () => await verifyOkTest(zkconsVK, zkconsProof));
	it("zkcons: shouldn't verify incorrect proof",  async () => await verifyWrongProof(zkconsVK, zkconsProof));
	it("zkcons: shouldn't verify incorrect input",  async () => await verifyWrongInput(zkconsVK, zkconsProof));

	it("zkconf: should set verifying key",          async () => await setkeyTest(zkconfVK, zkconfProof));
	it("zkconf: should verify correct proof",       async () => await verifyOkTest(zkconfVK, zkconfProof));
	it("zkconf: shouldn't verify incorrect proof",  async () => await verifyWrongProof(zkconfVK, zkconfProof));
	it("zkconf: shouldn't verify incorrect input",  async () => await verifyWrongInput(zkconfVK, zkconfProof));
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

