#!/usr/bin/env python3

# AlexZ: This code is entirly based on the Zeth test_pairing.py 
#        Just stripping some code to reduce the dependencies...
#        /snarks/depends/zeth/client/zeth/core/test_pairing.py
# 
#       Run: python3 -m unittest -v

# Copyright (c) 2015-2021 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

from pairing import PairingParameters, G1Point, G2Point, \
    g1_point_negate, g2_point_negate

from unittest import TestCase

# pylint: disable=line-too-long
ALT_BN128_PAIRING = PairingParameters.from_json_dict({
    "name": "alt-bn128",
    "r": "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
    "q": "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
    "generator_g1": [
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000000000000000000000000000002"
    ],
    "generator_g2": [
        ["0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
         "0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"],
        ["0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b",
         "0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"],
    ]
})

ALT_BN128_G1_MINUS_1 = G1Point.from_json_list([
    "0x0000000000000000000000000000000000000000000000000000000000000001",
    "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"])

ALT_BN128_G1_8 = G1Point.from_json_list([
    "0x08b1d51d23480c10f472f5e93b9cfea88238c121fe155af7043937882c306a63",
    "0x299836713dad3fa34e337aa412466015c366af8ec50b9d7bd05aa74642822021"])

ALT_BN128_G1_MINUS_8 = G1Point.from_json_list([
    "0x08b1d51d23480c10f472f5e93b9cfea88238c121fe155af7043937882c306a63",
    "0x06cc1801a38460866a1ccb126f3af847d41abb02a3662d116bc5e4d095fadd26"])

ALT_BN128_G2_MINUS_1 = G2Point.from_json_list([
    ["0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
     "0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"],
    ["0x275dc4a288d1afb3cbb1ac09187524c7db36395df7be3b99e673b13a075a65ec",
     "0x1d9befcd05a5323e6da4d435f3b617cdb3af83285c2df711ef39c01571827f9d"]])

ALT_BN128_G2_8 = G2Point.from_json_list([
    ["0x03589520df85791604b5a2b720a21139aabdb41949d47779484b0db588bfa699",
     "0x18afc7fd8df1c902383c213b6d989f0066b7eca1388be49721792278984d9a29"],
    ["0x2cc25982f4a3b75f57f8f3e966d75e6da8c51776bf0828c7ce3f10171793cd2a",
     "0x17623e9e90176bcdf8454daa96008240b12709ca5d79de805744cfd137609bec"]])

ALT_BN128_G2_MINUS_8 = G2Point.from_json_list([
    ["0x03589520df85791604b5a2b720a21139aabdb41949d47779484b0db588bfa699",
     "0x18afc7fd8df1c902383c213b6d989f0066b7eca1388be49721792278984d9a29"],
    ["0x03a1f4efec8de8ca605751cd1aa9f9efeebc531aa969a1c56de17bffc0e9301d",
     "0x19020fd4511a345bc00af80beb80d61ce65a60c70af7ec0ce4dbbc45a11c615b"]])


# pylint: enable=line-too-long


class TestPairing(TestCase):

    def test_pairing_json(self) -> None:
        self._do_test_pairing_json(ALT_BN128_PAIRING)

    def test_alt_bn128_negate_g1(self) -> None:
        self._do_test_negate_g1(
            ALT_BN128_PAIRING,
            ALT_BN128_PAIRING.generator_g1,
            ALT_BN128_G1_MINUS_1)
        self._do_test_negate_g1(
            ALT_BN128_PAIRING,
            ALT_BN128_G1_8,
            ALT_BN128_G1_MINUS_8)

    def test_alt_bn128_negate_g2(self) -> None:
        self._do_test_negate_g2(
            ALT_BN128_PAIRING,
            ALT_BN128_PAIRING.generator_g2,
            ALT_BN128_G2_MINUS_1)
        self._do_test_negate_g2(
            ALT_BN128_PAIRING,
            ALT_BN128_G2_8,
            ALT_BN128_G2_MINUS_8)

    def _do_test_pairing_json(self, pp: PairingParameters) -> None:
        pp_encoded = pp.to_json_dict()
        pp_decoded = PairingParameters.from_json_dict(pp_encoded)
        self.assertEqual(pp.to_json_dict(), pp_decoded.to_json_dict())

    def _do_test_negate_g1(
            self,
            pp: PairingParameters,
            element: G1Point,
            minus_element: G1Point) -> None:
        negated_element = g1_point_negate(element, pp)
        self.assertEqual(minus_element, negated_element)

    def _do_test_negate_g2(
            self,
            pp: PairingParameters,
            element: G2Point,
            minus_element: G2Point) -> None:
        negated_element = g2_point_negate(element, pp)
        self.assertEqual(minus_element, negated_element)
