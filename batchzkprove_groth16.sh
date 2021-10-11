#!/usr/bin/bash

echo "======================================"
echo "Generating Groth16 Proofs zkConsent"
echo "======================================"

echo
./snarks/build/zkconsent/zkconsent prove --groth16 --zkterminate   -w ./samples/zkterminate.json
./snarks/build/zkconsent/zkconsent prove --groth16 --zkmint        -w ./samples/zkmint.json
./snarks/build/zkconsent/zkconsent prove --groth16 --zkconsent     -w ./samples/zkconsent.json
./snarks/build/zkconsent/zkconsent prove --groth16 --zkconfconsent -w ./samples/zkconfconsent.json

./snarks/build/zkconsent/zkconsent prove --groth16 --zkterminate -w ./samples/zkterminate_other.json \
            --extproof-json $HOME/zkconsent_setup/groth16/other/zkterm/exproof_zkterm.json \
            --proof-bin     $HOME/zkconsent_setup/groth16/other/zkterm/proof_zkterm.bin \
            --primary-bin   $HOME/zkconsent_setup/groth16/other/zkterm/primary_zkterm.bin \
            --witness-bin   $HOME/zkconsent_setup/groth16/other/zkterm/witness_zkterm.bin

./snarks/build/zkconsent/zkconsent prove --groth16 --zkmint      -w ./samples/zkmint_other.json \
            --extproof-json $HOME/zkconsent_setup/groth16/other/zkmint/exproof_zkmint.json  \
            --proof-bin     $HOME/zkconsent_setup/groth16/other/zkmint/proof_zkmint.bin \
            --primary-bin   $HOME/zkconsent_setup/groth16/other/zkmint/primary_zkmint.bin \
            --witness-bin   $HOME/zkconsent_setup/groth16/other/zkmint/witness_zkmint.bin

./snarks/build/zkconsent/zkconsent prove --groth16 --zkconsent   -w ./samples/zkconsent_other.json \
            --extproof-json $HOME/zkconsent_setup/groth16/other/zkcons/exproof_zkcons.json \
            --proof-bin     $HOME/zkconsent_setup/groth16/other/zkcons/proof_zkcons.bin \
            --primary-bin   $HOME/zkconsent_setup/groth16/other/zkcons/primary_zkcons.bin \
            --witness-bin   $HOME/zkconsent_setup/groth16/other/zkcons/witness_zkcons.bin

./snarks/build/zkconsent/zkconsent prove --groth16 --zkconfconsent -w ./samples/zkconfconsent_other.json \
            --extproof-json $HOME/zkconsent_setup/groth16/other/zkconfcons/exproof_zkconfcons.json \
            --proof-bin     $HOME/zkconsent_setup/groth16/other/zkconfcons/proof_zkconfcons.bin \
            --primary-bin   $HOME/zkconsent_setup/groth16/other/zkconfcons/primary_zkconfcons.bin \
            --witness-bin   $HOME/zkconsent_setup/groth16/other/zkconfcons/witness_zkconfcons.bin


python3 ./verifier/groth16_hlp/convertvk.py    $HOME/zkconsent_setup/groth16/zkterm/vk_zkterm.json $HOME/zkconsent_setup/groth16/zkterm/vk_zkterm_params.json
python3 ./verifier/groth16_hlp/convertvk.py    $HOME/zkconsent_setup/groth16/zkmint/vk_zkmint.json $HOME/zkconsent_setup/groth16/zkmint/vk_zkmint_params.json
python3 ./verifier/groth16_hlp/convertvk.py    $HOME/zkconsent_setup/groth16/zkcons/vk_zkcons.json $HOME/zkconsent_setup/groth16/zkcons/vk_zkcons_params.json
python3 ./verifier/groth16_hlp/convertvk.py    $HOME/zkconsent_setup/groth16/zkconfcons/vk_zkconfcons.json $HOME/zkconsent_setup/groth16/zkconfcons/vk_zkconfcons_params.json

python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/zkterm/exproof_zkterm.json $HOME/zkconsent_setup/groth16/zkterm/exproof_zkterm_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/zkmint/exproof_zkmint.json $HOME/zkconsent_setup/groth16/zkmint/exproof_zkmint_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/zkcons/exproof_zkcons.json $HOME/zkconsent_setup/groth16/zkcons/exproof_zkcons_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/zkconfcons/exproof_zkconfcons.json $HOME/zkconsent_setup/groth16/zkconfcons/exproof_zkconfcons_params.json

python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/other/zkterm/exproof_zkterm.json $HOME/zkconsent_setup/groth16/other/zkterm/exproof_zkterm_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/other/zkmint/exproof_zkmint.json $HOME/zkconsent_setup/groth16/other/zkmint/exproof_zkmint_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/other/zkcons/exproof_zkcons.json $HOME/zkconsent_setup/groth16/other/zkcons/exproof_zkcons_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/other/zkconfcons/exproof_zkconfcons.json $HOME/zkconsent_setup/groth16/other/zkconfcons/exproof_zkconfcons_params.json
