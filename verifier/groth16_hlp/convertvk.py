#!/usr/bin/env python3
   

# Python program to read
# json file

# convertvk.py  $HOME/zkconsent_setup/groth16/zkterm/vk_zkterm.json $HOME/zkconsent_setup/groth16/zkterm/vk_zkterm_params.json

from utils import int_to_hex
from zksnark import Groth16
from test_pairing import ALT_BN128_PAIRING

import sys
import json
from os.path import exists

print()
print()
print("Usage: convertvk.py <input json> <output json>")
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

vk   = Groth16.VerificationKey.from_json_dict(jsondata)
vk_parameters = Groth16.verification_key_to_contract_parameters(
    vk, ALT_BN128_PAIRING)

hexvals = []
for int_val in vk_parameters:
    hexvals.append(int_to_hex(int_val,32))

print()
print()
print("Verification Key:")
print(json.dumps(vk.to_json_dict(), indent=4))
print()
print("Contract uint Key:")
print(json.dumps(vk_parameters, indent=4))
print()
print("Contract Hex Key:")
print(json.dumps(hexvals, indent=4))
print()

with open(sys.argv[2], "w") as outfile:
    json.dump(hexvals, outfile, indent=4)

