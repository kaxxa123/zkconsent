#!/usr/bin/bash

echo "======================================"
echo "Generating Groth16 Proofs zkConsent"
echo "======================================"

echo
./snarks/build/zkconsent/zkconsent prove --groth16 --zkterminate -w ./samples/zkterminate.json
./snarks/build/zkconsent/zkconsent prove --groth16 --zkmint      -w ./samples/zkmint.json
./snarks/build/zkconsent/zkconsent prove --groth16 --zkconsent   -w ./samples/zkconsent.json
./snarks/build/zkconsent/zkconsent prove --groth16 --zkconfirm   -w ./samples/zkconfirm.json

./snarks/build/zkconsent/zkconsent prove --groth16 --zkterminate -w ./samples/zkterminate_other.json --extproof-json $HOME/zkconsent_setup/other/groth16/zkterm/exproof_zkterm.json --proof-bin $HOME/zkconsent_setup/other/groth16/zkterm/proof_zkterm.bin --primary-bin $HOME/zkconsent_setup/other/groth16/zkterm/primary_zkterm.bin --witness-bin $HOME/zkconsent_setup/other/groth16/zkterm/witness_zkterm.bin
./snarks/build/zkconsent/zkconsent prove --groth16 --zkmint      -w ./samples/zkmint_other.json      --extproof-json $HOME/zkconsent_setup/other/groth16/zkmint/exproof_zkmint.json --proof-bin $HOME/zkconsent_setup/other/groth16/zkmint/proof_zkmint.bin --primary-bin $HOME/zkconsent_setup/other/groth16/zkmint/primary_zkmint.bin --witness-bin $HOME/zkconsent_setup/other/groth16/zkmint/witness_zkmint.bin
./snarks/build/zkconsent/zkconsent prove --groth16 --zkconsent   -w ./samples/zkconsent.json         --extproof-json $HOME/zkconsent_setup/other/groth16/zkcons/exproof_zkcons.json --proof-bin $HOME/zkconsent_setup/other/groth16/zkcons/proof_zkcons.bin --primary-bin $HOME/zkconsent_setup/other/groth16/zkcons/primary_zkcons.bin --witness-bin $HOME/zkconsent_setup/other/groth16/zkcons/witness_zkcons.bin
./snarks/build/zkconsent/zkconsent prove --groth16 --zkconfirm   -w ./samples/zkconfirm.json         --extproof-json $HOME/zkconsent_setup/other/groth16/zkconf/exproof_zkconf.json --proof-bin $HOME/zkconsent_setup/other/groth16/zkconf/proof_zkconf.bin --primary-bin $HOME/zkconsent_setup/other/groth16/zkconf/primary_zkconf.bin --witness-bin $HOME/zkconsent_setup/other/groth16/zkconf/witness_zkconf.bin

python3 ./verifier/groth16_hlp/convertvk.py $HOME/zkconsent_setup/groth16/zkterm/vk_zkterm.json $HOME/zkconsent_setup/groth16/zkterm/vk_zkterm_params.json
python3 ./verifier/groth16_hlp/convertvk.py $HOME/zkconsent_setup/groth16/zkmint/vk_zkmint.json $HOME/zkconsent_setup/groth16/zkmint/vk_zkmint_params.json
python3 ./verifier/groth16_hlp/convertvk.py $HOME/zkconsent_setup/groth16/zkcons/vk_zkcons.json $HOME/zkconsent_setup/groth16/zkcons/vk_zkcons_params.json
python3 ./verifier/groth16_hlp/convertvk.py $HOME/zkconsent_setup/groth16/zkconf/vk_zkconf.json $HOME/zkconsent_setup/groth16/zkconf/vk_zkconf_params.json

python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/zkterm/exproof_zkterm.json $HOME/zkconsent_setup/groth16/zkterm/exproof_zkterm_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/zkmint/exproof_zkmint.json $HOME/zkconsent_setup/groth16/zkmint/exproof_zkmint_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/zkcons/exproof_zkcons.json $HOME/zkconsent_setup/groth16/zkcons/exproof_zkcons_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/zkconf/exproof_zkconf.json $HOME/zkconsent_setup/groth16/zkconf/exproof_zkconf_params.json

python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/other/groth16/zkterm/exproof_zkterm.json $HOME/zkconsent_setup/other/groth16/zkterm/exproof_zkterm_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/other/groth16/zkmint/exproof_zkmint.json $HOME/zkconsent_setup/other/groth16/zkmint/exproof_zkmint_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/other/groth16/zkcons/exproof_zkcons.json $HOME/zkconsent_setup/other/groth16/zkcons/exproof_zkcons_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/other/groth16/zkconf/exproof_zkconf.json $HOME/zkconsent_setup/other/groth16/zkconf/exproof_zkconf_params.json
