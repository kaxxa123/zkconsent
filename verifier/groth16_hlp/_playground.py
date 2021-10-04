#!/usr/bin/env python3
   
from __future__ import annotations

from pairing import PairingParameters, G1Point, g1_point_to_contract_parameters, \
    G2Point, g2_point_to_contract_parameters, g2_point_negate

import json
from abc import (ABC, abstractmethod)
from math import log, floor
from typing import Dict, Sequence, List, Tuple, Union, Iterable, Any, Optional, cast

# Map from the pairing name (on PairingParameters) to contract name fragment,
# used in contract naming conventions.
PAIRING_NAME_TO_CONTRACT_NAME = {
    "alt-bn128": "AltBN128",
    "bls12-377": "BLS12_377",
}

class Groth16:

    class VerificationKey:
        def __init__(
                self,
                alpha: G1Point,
                beta: G2Point,
                delta: G2Point,
                abc: List[G1Point]):
            self.alpha = alpha
            self.beta = beta
            self.delta = delta
            self.abc = abc

        def to_json_dict(self) -> Dict[str, Any]:
            return {
                "alpha": self.alpha.to_json_list(),
                "beta": self.beta.to_json_list(),
                "delta": self.delta.to_json_list(),
                "ABC": [abc.to_json_list() for abc in self.abc],
            }

        @staticmethod
        def from_json_dict(json_dict: Dict[str, Any]) -> Groth16.VerificationKey:
            return Groth16.VerificationKey(
                alpha=G1Point.from_json_list(json_dict["alpha"]),
                beta=G2Point.from_json_list(json_dict["beta"]),
                delta=G2Point.from_json_list(json_dict["delta"]),
                abc=[G1Point.from_json_list(abc)
                     for abc in json_dict["ABC"]])

    class Proof:
        def __init__(
                self,
                a: G1Point,
                b: G2Point,
                c: G1Point):
            self.a = a
            self.b = b
            self.c = c

        def to_json_dict(self) -> Dict[str, Any]:
            return {
                "a": self.a.to_json_list(),
                "b": self.b.to_json_list(),
                "c": self.c.to_json_list(),
            }

        @staticmethod
        def from_json_dict(json_dict: Dict[str, Any]) -> Groth16.Proof:
            return Groth16.Proof(
                a=G1Point.from_json_list(json_dict["a"]),
                b=G2Point.from_json_list(json_dict["b"]),
                c=G1Point.from_json_list(json_dict["c"]))

    @staticmethod
    def get_contract_name(pp: PairingParameters) -> str:
        return _contract_name("Groth16", pp)

    @staticmethod
    def verification_key_to_contract_parameters(
            vk: Groth16.VerificationKey,
            pp: PairingParameters) -> List[int]:
        assert isinstance(vk, Groth16.VerificationKey)
        minus_beta = g2_point_negate(vk.beta, pp)
        minus_delta = g2_point_negate(vk.delta, pp)
        return \
            g1_point_to_contract_parameters(vk.alpha) + \
            g2_point_to_contract_parameters(minus_beta) + \
            g2_point_to_contract_parameters(minus_delta) + \
            sum(
                [g1_point_to_contract_parameters(abc)
                 for abc in vk.abc],
                [])

    @staticmethod
    def verification_key_from_json_dict(
            json_dict: Dict[str, Any]) -> Groth16.VerificationKey:
        return Groth16.VerificationKey.from_json_dict(json_dict)

    @staticmethod
    def proof_from_json_dict(json_dict: Dict[str, Any]) -> Groth16.Proof:
        return Groth16.Proof.from_json_dict(json_dict)

    @staticmethod
    def proof_to_contract_parameters(
            proof: Groth16.Proof, pp: PairingParameters) -> List[int]:
        assert isinstance(proof, Groth16.Proof)
        return \
            g1_point_to_contract_parameters(proof.a) + \
            g2_point_to_contract_parameters(proof.b) + \
            g1_point_to_contract_parameters(proof.c)

def _contract_name(zksnark_name: str, pp: PairingParameters) -> str:
    """
    Given a snark name fragment (as used in contract naming conventions) and
    pairing parameters, determine the full contract name.
    """
    return "Mixer" + zksnark_name + PAIRING_NAME_TO_CONTRACT_NAME[pp.name]



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

ptG1 = G1Point("01","01")
print(ptG1.to_json_list())
print(g1_point_to_contract_parameters(ptG1))
print()


ptG2 = G2Point(["01","01"], ["02","02"])
print(ptG2.to_json_list())
print(g2_point_to_contract_parameters(ptG2))


