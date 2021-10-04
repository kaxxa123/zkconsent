#!/usr/bin/env python3
   

# Python program to read
# json file

# convertproof.py  $HOME/zkconsent_setup/groth16/zkterm/exproof_zkterm.json  $HOME/zkconsent_setup/groth16/zkterm/exproof_zkterm_params.json

from utils import int_to_hex
from zksnark import Groth16
from test_pairing import ALT_BN128_PAIRING

import sys
import json
from os.path import exists

print()
print()
print("Usage: convertproof.py <input json> <output json>")
print()
print()

if len(sys.argv) != 3:
    print("Missing/too many parameters")
    sys.exit()

if not exists(sys.argv[1]):
    print("Input json not found!")
    sys.exit()


# Opening JSON file
jsonfile = open(sys.argv[1],)
jsondata = json.load(jsonfile)
jsonfile.close()

proof   = Groth16.Proof.from_json_dict(jsondata['proof'])
proof_parameters = Groth16.proof_to_contract_parameters(
    proof, ALT_BN128_PAIRING)

hexvals = []
for int_val in proof_parameters:
    hexvals.append(int_to_hex(int_val,32))

print()
print()
print("Proof:")
print(json.dumps(proof.to_json_dict(), indent=4))
print()
print("Contract uint Proof:")
print(json.dumps(proof_parameters, indent=4))
print()
print("Contract Hex Proof:")
print(json.dumps(hexvals, indent=4))
print()

with open(sys.argv[2], "w") as outfile:
    json.dump(hexvals, outfile, indent=4)

