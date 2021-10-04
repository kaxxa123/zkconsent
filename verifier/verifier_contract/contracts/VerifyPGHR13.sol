pragma solidity ^0.6.1;

import "./BN128_Libraries.sol";
// SPDX-License-Identifier: LGPL-3.0+

//
//AlexZ: This code is based on the verifier code provided in this tutorial
//       https://github.com/christianlundkvist/libsnark-tutorial/blob/master/src/ethereum/contracts/Verifier.sol
//
// Changes:
//     Migrating code to solidity v0.6.x
//
//     Updates to function names to use the BN128 libraries as generated 
//     by the latest zokrates build.

contract VerifyPGHR13 {
    
    struct VerifyingKey {
        Pairing.G2Point A;
        Pairing.G1Point B;
        Pairing.G2Point C;
        Pairing.G2Point gamma;
        Pairing.G1Point gammaBeta1;
        Pairing.G2Point gammaBeta2;
        Pairing.G2Point Z;
        Pairing.G1Point[] IC;
    }

    struct Proof {
        Pairing.G1Point A;
        Pairing.G1Point A_p;
        Pairing.G2Point B;
        Pairing.G1Point B_p;
        Pairing.G1Point C;
        Pairing.G1Point C_p;
        Pairing.G1Point K;
        Pairing.G1Point H;
    }

    bool public verifyingKeySet = false;
    VerifyingKey vk;

    function setVerifyingKey(
            uint[2][2] memory A,
            uint[2] memory B,
            uint[2][2] memory C,
            uint[2][2] memory gamma,
            uint[2] memory gamma_beta_1,
            uint[2][2] memory gamma_beta_2,
            uint[2][2] memory Z,
            uint[2][] memory IC) public {
    	require(!verifyingKeySet);

        vk.A = Pairing.G2Point([A[0][0], A[0][1]], [A[1][0], A[1][1]]);
        vk.B = Pairing.G1Point(B[0], B[1]);
        vk.C = Pairing.G2Point([C[0][0], C[0][1]], [C[1][0], C[1][1]]);
        vk.gamma = Pairing.G2Point([gamma[0][0], gamma[0][1]], [gamma[1][0], gamma[1][1]]);
        vk.gammaBeta1 = Pairing.G1Point(gamma_beta_1[0], gamma_beta_1[1]);
        vk.gammaBeta2 = Pairing.G2Point([gamma_beta_2[0][0], gamma_beta_2[0][1]], [gamma_beta_2[1][0], gamma_beta_2[1][1]]);
        vk.Z = Pairing.G2Point([Z[0][0], Z[0][1]], [Z[1][0], Z[1][1]]);

        for(uint iCnt = 0; iCnt < IC.length; iCnt++) {
            vk.IC.push(Pairing.G1Point(IC[iCnt][0], IC[iCnt][1]));
        }
        verifyingKeySet = true;
    }
    
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        require(input.length + 1 == vk.IC.length);

        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++)
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.IC[i + 1], input[i]));

        vk_x = Pairing.addition(vk_x, vk.IC[0]);
        if (!Pairing.pairingProd2(proof.A, vk.A, Pairing.negate(proof.A_p), Pairing.P2())) return 1;
        if (!Pairing.pairingProd2(vk.B, proof.B, Pairing.negate(proof.B_p), Pairing.P2())) return 2;
        if (!Pairing.pairingProd2(proof.C, vk.C, Pairing.negate(proof.C_p), Pairing.P2())) return 3;
        if (!Pairing.pairingProd3(
            proof.K, vk.gamma,
            Pairing.negate(Pairing.addition(vk_x, Pairing.addition(proof.A, proof.C))), vk.gammaBeta2,
            Pairing.negate(vk.gammaBeta1), proof.B
        )) return 4;
        if (!Pairing.pairingProd3(
                Pairing.addition(vk_x, proof.A), proof.B,
                Pairing.negate(proof.H), vk.Z,
                Pairing.negate(proof.C), Pairing.P2()
        )) return 5;
        return 0;
    }

    function verifyTx(
            uint[2] memory a,
            uint[2] memory a_p,
            uint[2][2] memory b,
            uint[2] memory b_p,
            uint[2] memory c,
            uint[2] memory c_p,
            uint[2] memory h,
            uint[2] memory k,
            uint[] memory input) public view returns (bool) {
        require(verifyingKeySet);
        Proof memory proof;
        proof.A     = Pairing.G1Point(a[0], a[1]);
        proof.A_p   = Pairing.G1Point(a_p[0], a_p[1]);
        proof.B     = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.B_p   = Pairing.G1Point(b_p[0], b_p[1]);
        proof.C     = Pairing.G1Point(c[0], c[1]);
        proof.C_p   = Pairing.G1Point(c_p[0], c_p[1]);
        proof.H     = Pairing.G1Point(h[0], h[1]);
        proof.K     = Pairing.G1Point(k[0], k[1]);

        uint[] memory inputValues = new uint[](input.length);
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }

        return (verify(inputValues, proof) == 0);
    }
}
