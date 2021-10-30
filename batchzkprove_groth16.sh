#!/usr/bin/bash

echo "======================================"
echo "Generating Groth16 Proofs zkConsent"
echo "======================================"

mkdir -p $HOME/zkconsent_logs/groth16

echo
./snarks/build/zkconsent/zkconsent prove --groth16 --zkterminate     -w ./samples/zkterminate.json \
            | tee $HOME/zkconsent_logs/groth16/zkterm_proof.log

./snarks/build/zkconsent/zkconsent prove --groth16 --zkmint          -w ./samples/zkmint.json \
            | tee $HOME/zkconsent_logs/groth16/zkmint_proof.log

./snarks/build/zkconsent/zkconsent prove --groth16 --zkconsent       -w ./samples/zkconsent.json \
            | tee $HOME/zkconsent_logs/groth16/zkcons_proof.log

./snarks/build/zkconsent/zkconsent prove --groth16 --zkconfconsent   -w ./samples/zkconfconsent.json \
            | tee $HOME/zkconsent_logs/groth16/zkconsconf_proof.log

./snarks/build/zkconsent/zkconsent prove --groth16 --zkconfterminate -w ./samples/zkconfterminate.json \
            | tee $HOME/zkconsent_logs/groth16/zktermconf_proof.log


./snarks/build/zkconsent/zkconsent prove --groth16 --zkterminate -w ./samples/zkterminate_other.json \
            --extproof-json $HOME/zkconsent_setup/groth16/other/zkterm/exproof_zkterm.json \
            --proof-bin     $HOME/zkconsent_setup/groth16/other/zkterm/proof_zkterm.bin \
            --primary-bin   $HOME/zkconsent_setup/groth16/other/zkterm/primary_zkterm.bin \
            --witness-bin   $HOME/zkconsent_setup/groth16/other/zkterm/witness_zkterm.bin \
            | tee $HOME/zkconsent_logs/groth16/zkterm_proofother.log

./snarks/build/zkconsent/zkconsent prove --groth16 --zkmint      -w ./samples/zkmint_other.json \
            --extproof-json $HOME/zkconsent_setup/groth16/other/zkmint/exproof_zkmint.json  \
            --proof-bin     $HOME/zkconsent_setup/groth16/other/zkmint/proof_zkmint.bin \
            --primary-bin   $HOME/zkconsent_setup/groth16/other/zkmint/primary_zkmint.bin \
            --witness-bin   $HOME/zkconsent_setup/groth16/other/zkmint/witness_zkmint.bin \
            | tee $HOME/zkconsent_logs/groth16/zkmint_proofother.log

./snarks/build/zkconsent/zkconsent prove --groth16 --zkconsent   -w ./samples/zkconsent_other.json \
            --extproof-json $HOME/zkconsent_setup/groth16/other/zkcons/exproof_zkcons.json \
            --proof-bin     $HOME/zkconsent_setup/groth16/other/zkcons/proof_zkcons.bin \
            --primary-bin   $HOME/zkconsent_setup/groth16/other/zkcons/primary_zkcons.bin \
            --witness-bin   $HOME/zkconsent_setup/groth16/other/zkcons/witness_zkcons.bin \
            | tee $HOME/zkconsent_logs/groth16/zkcons_proofother.log

./snarks/build/zkconsent/zkconsent prove --groth16 --zkconfconsent -w ./samples/zkconfconsent_other.json \
            --extproof-json $HOME/zkconsent_setup/groth16/other/zkconfcons/exproof_zkconfcons.json \
            --proof-bin     $HOME/zkconsent_setup/groth16/other/zkconfcons/proof_zkconfcons.bin \
            --primary-bin   $HOME/zkconsent_setup/groth16/other/zkconfcons/primary_zkconfcons.bin \
            --witness-bin   $HOME/zkconsent_setup/groth16/other/zkconfcons/witness_zkconfcons.bin \
            | tee $HOME/zkconsent_logs/groth16/zkconsconf_proofother.log

./snarks/build/zkconsent/zkconsent prove --groth16 --zkconfterminate -w ./samples/zkconfterminate_other.json \
            --extproof-json $HOME/zkconsent_setup/groth16/other/zkconfterm/exproof_zkconfterm.json \
            --proof-bin     $HOME/zkconsent_setup/groth16/other/zkconfterm/proof_zkconfterm.bin \
            --primary-bin   $HOME/zkconsent_setup/groth16/other/zkconfterm/primary_zkconfterm.bin \
            --witness-bin   $HOME/zkconsent_setup/groth16/other/zkconfterm/witness_zkconfterm.bin \
            | tee $HOME/zkconsent_logs/groth16/zktermconf_proofother.log


python3 ./verifier/groth16_hlp/convertvk.py    $HOME/zkconsent_setup/groth16/zkterm/vk_zkterm.json $HOME/zkconsent_setup/groth16/zkterm/vk_zkterm_params.json
python3 ./verifier/groth16_hlp/convertvk.py    $HOME/zkconsent_setup/groth16/zkmint/vk_zkmint.json $HOME/zkconsent_setup/groth16/zkmint/vk_zkmint_params.json
python3 ./verifier/groth16_hlp/convertvk.py    $HOME/zkconsent_setup/groth16/zkcons/vk_zkcons.json $HOME/zkconsent_setup/groth16/zkcons/vk_zkcons_params.json
python3 ./verifier/groth16_hlp/convertvk.py    $HOME/zkconsent_setup/groth16/zkconfcons/vk_zkconfcons.json $HOME/zkconsent_setup/groth16/zkconfcons/vk_zkconfcons_params.json
python3 ./verifier/groth16_hlp/convertvk.py    $HOME/zkconsent_setup/groth16/zkconfterm/vk_zkconfterm.json $HOME/zkconsent_setup/groth16/zkconfterm/vk_zkconfterm_params.json

python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/zkterm/exproof_zkterm.json $HOME/zkconsent_setup/groth16/zkterm/exproof_zkterm_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/zkmint/exproof_zkmint.json $HOME/zkconsent_setup/groth16/zkmint/exproof_zkmint_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/zkcons/exproof_zkcons.json $HOME/zkconsent_setup/groth16/zkcons/exproof_zkcons_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/zkconfcons/exproof_zkconfcons.json $HOME/zkconsent_setup/groth16/zkconfcons/exproof_zkconfcons_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/zkconfterm/exproof_zkconfterm.json $HOME/zkconsent_setup/groth16/zkconfterm/exproof_zkconfterm_params.json

python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/other/zkterm/exproof_zkterm.json $HOME/zkconsent_setup/groth16/other/zkterm/exproof_zkterm_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/other/zkmint/exproof_zkmint.json $HOME/zkconsent_setup/groth16/other/zkmint/exproof_zkmint_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/other/zkcons/exproof_zkcons.json $HOME/zkconsent_setup/groth16/other/zkcons/exproof_zkcons_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/other/zkconfcons/exproof_zkconfcons.json $HOME/zkconsent_setup/groth16/other/zkconfcons/exproof_zkconfcons_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/other/zkconfterm/exproof_zkconfterm.json $HOME/zkconsent_setup/groth16/other/zkconfterm/exproof_zkconfterm_params.json
