#!/usr/bin/env python3

# AlexZ: This code is entirly based on Zeth
#        Just stripping some code to reduce the dependencies...
# 
#       Run: python3 -m unittest -v

# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from zksnark import ExtendedProof, Groth16
from test_pairing import ALT_BN128_PAIRING
from unittest import TestCase

# pylint: disable=line-too-long
VERIFICATION_KEY_ALT_BN128_GROTH16 = Groth16.VerificationKey.from_json_dict({
    "alpha": [
        "0x009d7309d79d5215384a7a9a1d9372af909582781f388a51cb833c87b8024519",
        "0x012816ef6069ef1e40eaab0a111f9b98b276dbf2a3209d788eb8ce635ce92a29",
    ],
    "beta": [[
        "0x017abb9470ccb0ef09676df87dbe181a9ed89ba1cf1e32a2031d308b4c11a84f",
        "0x01774daba40ce4c9fe2d2c6d17a3821b31ec63a77ebea2dab8b3218fd7eb90f9",
    ], [
        "0x18ce3769d0c1e29aa799a5928b1c524a5a85326c4b16463530bfdcab82f55ef6",
        "0x1a9234f3340fb85ae722ed052b8dcf63193c423791d9c43ab725a35286bda170",
    ]],
    "delta": [[
        "0x19c19b1795e634573c0514de0cea5bd05d88c24b08aeadc03ec4686ee6741b80",
        "0x01a00d16c4d2805e248debf48ea0771e627e2bfb95198df0cbe09a1eb4879fe5",
    ], [
        "0x00361ca07388d760898e0969f3b9a3d6d751b83d770007761e1c5cc798852ed8",
        "0x009a7d27c8392eefe1ba23a52d509cda59ba3c5acc95765d1146a998c780277f",
    ]],
    "ABC": [[
        "0x01098a772e5fb9edbbd68943000e46bb0f3f2514cbbe1ef15ba485d1c07a6836",
        "0x18a94eefa95142069e1f1c069d48645201d1201bc0b7d9bc25ee65a25602362f",
    ], [
        "0x1a4cfba533c731398e06458003ef7c3920dd1a545b469cc0c35dc19c51942c15",
        "0x06194ebb25bab4d163005b23e9cf9aa8d43d242a7792f0fcf269549b46bcc217",
    ]]
})

# Encoded as evm uint256_t words (note beta and delta are negated)
VERIFICATION_KEY_ALT_BN128_GROTH16_PARAMETERS = [
    # Alpha
    int("0x009d7309d79d5215384a7a9a1d9372af909582781f388a51cb833c87b8024519", 16),  # noqa
    int("0x012816ef6069ef1e40eaab0a111f9b98b276dbf2a3209d788eb8ce635ce92a29", 16),  # noqa
    # Minus Beta
    int("0x017abb9470ccb0ef09676df87dbe181a9ed89ba1cf1e32a2031d308b4c11a84f", 16),  # noqa
    int("0x01774daba40ce4c9fe2d2c6d17a3821b31ec63a77ebea2dab8b3218fd7eb90f9", 16),  # noqa
    int("0x17961709106fbd8f10b6a023f66506133cfc38251d5b84580b60af6b55879e51", 16),  # noqa
    int("0x15d2197fad21e7ced12d58b155f388fa7e452859d698065284fae8c451bf5bd7", 16),  # noqa
    # Minus Delta
    int("0x19c19b1795e634573c0514de0cea5bd05d88c24b08aeadc03ec4686ee6741b80", 16),  # noqa
    int("0x01a00d16c4d2805e248debf48ea0771e627e2bfb95198df0cbe09a1eb4879fe5", 16),  # noqa
    int("0x302e31d26da8c8c92ec23c4c8dc7b486c02fb253f171c3171e042f4f3ff7ce6f", 16),  # noqa
    int("0x2fc9d14b18f87139d69622115430bb833dc72e369bdc54302ad9e27e10fcd5c8", 16),  # noqa
    # ABC
    int("0x01098a772e5fb9edbbd68943000e46bb0f3f2514cbbe1ef15ba485d1c07a6836", 16),  # noqa
    int("0x18a94eefa95142069e1f1c069d48645201d1201bc0b7d9bc25ee65a25602362f", 16),  # noqa
    int("0x1a4cfba533c731398e06458003ef7c3920dd1a545b469cc0c35dc19c51942c15", 16),  # noqa
    int("0x06194ebb25bab4d163005b23e9cf9aa8d43d242a7792f0fcf269549b46bcc217", 16),  # noqa
]

EXTPROOF_ALT_BN128_GROTH16 = ExtendedProof(
    proof=Groth16.Proof.from_json_dict({
        "a": [
            "0xbd3c06ed5aeb1a7b0653ba63f413b27ba7fd1b77cb4a403fb15f9fb8735abda9",  # noqa
            "0x55a73b1247dcfd62171b29ddbd271cdb7e98b78912ddf6bfe4723cd229f414f9"  # noqa
        ],
        "b": [
            [
                "0xda9239a53b094ae15473baaa3649afb46d5330f36f8590df668167dd02aaf0a1",  # noqa
                "0x38ce5525864aa135674b048bb68adadfabca2a4cea43ea13b19cacec1ae17198"  # noqa
            ],
            [
                "0x15a4ea0daaaf8ef20b37c4bda03c2d381be797ae59b621b841d3e61495cf2aaf",  # noqa
                "0x8d64383293780f481278fbb22ce1078d79180193361869d9e8639f028ac4c3a7"  # noqa
            ]
        ],
        "c": [
            "0x01c5d91872102ab1ca71b321f5e3b6aca698be9d8b432b8f1fc60c37bda88d6f",  # noqa
            "0xb34a2d07bba78abf1c3e909b1f691bb02f62991a6c6bab53c016e191ecf7929f"  # noqa
        ]
    }),
    inputs=[
        "0x0000000000000000000000000000000000000000000000000000000000000007"  # noqa
    ])

# Proof part of EXTPROOF_ALT_BN128_GROTH16 encoded as uint256_t words
PROOF_ALT_BN128_GROTH16_PARAMETERS = [
    # "a":
    int("0xbd3c06ed5aeb1a7b0653ba63f413b27ba7fd1b77cb4a403fb15f9fb8735abda9", 16),  # noqa
    int("0x55a73b1247dcfd62171b29ddbd271cdb7e98b78912ddf6bfe4723cd229f414f9", 16),  # noqa
    # "b":
    int("0xda9239a53b094ae15473baaa3649afb46d5330f36f8590df668167dd02aaf0a1", 16),  # noqa
    int("0x38ce5525864aa135674b048bb68adadfabca2a4cea43ea13b19cacec1ae17198", 16),  # noqa
    int("0x15a4ea0daaaf8ef20b37c4bda03c2d381be797ae59b621b841d3e61495cf2aaf", 16),  # noqa
    int("0x8d64383293780f481278fbb22ce1078d79180193361869d9e8639f028ac4c3a7", 16),  # noqa
    # "c":
    int("0x01c5d91872102ab1ca71b321f5e3b6aca698be9d8b432b8f1fc60c37bda88d6f", 16),  # noqa
    int("0xb34a2d07bba78abf1c3e909b1f691bb02f62991a6c6bab53c016e191ecf7929f", 16),  # noqa
]
# pylint: enable=line-too-long


class TestZKSnark(TestCase):

    def test_alt_bn128_groth16_verification_key_parameters(self) -> None:
        vk = VERIFICATION_KEY_ALT_BN128_GROTH16
        vk_parameters_expect = VERIFICATION_KEY_ALT_BN128_GROTH16_PARAMETERS
        vk_parameters = Groth16.verification_key_to_contract_parameters(
            vk, ALT_BN128_PAIRING)
        self.assertEqual(vk_parameters_expect, vk_parameters)
        print()
        print()
        print("Verification Key:")
        print(vk.to_json_dict())
        print()
        print("Contract Verification Key:")
        print(vk_parameters)
        print()

    def test_alt_bn128_groth16_proof_parameters(self) -> None:
        extproof = EXTPROOF_ALT_BN128_GROTH16
        proof_parameters = Groth16.proof_to_contract_parameters(
            extproof.proof, ALT_BN128_PAIRING)
        self.assertEqual(PROOF_ALT_BN128_GROTH16_PARAMETERS, proof_parameters)
        print()
        print()
        print("Extended Proof:")
        print(extproof.to_json_dict())
        print()
        print("Contract Proof Params:")
        print(proof_parameters)
        print()
