#!/usr/bin/bash

echo "=================================="
echo "Generating PGHR13 Proofs zkConsent"
echo "=================================="


echo
echo ">> SNARKs Prove"
./snarks/build/zkconsent/zkconsent prove --pghr13 --zkterminate -w ./samples/zkterminate.json
./snarks/build/zkconsent/zkconsent prove --pghr13 --zkmint      -w ./samples/zkmint.json
./snarks/build/zkconsent/zkconsent prove --pghr13 --zkconsent   -w ./samples/zkconsent.json
./snarks/build/zkconsent/zkconsent prove --pghr13 --zkconfirm   -w ./samples/zkconfirm.json

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkterminate -w ./samples/zkterminate.json \
            --extproof-json $HOME/zkconsent_setup/other/pghr13/zkterm/exproof_zkterm.json \
            --proof-bin     $HOME/zkconsent_setup/other/pghr13/zkterm/proof_zkterm.bin \
            --primary-bin   $HOME/zkconsent_setup/other/pghr13/zkterm/primary_zkterm.bin \
            --witness-bin   $HOME/zkconsent_setup/other/pghr13/zkterm/witness_zkterm.bin

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkmint      -w ./samples/zkmint.json \
            --extproof-json $HOME/zkconsent_setup/other/pghr13/zkmint/exproof_zkmint.json \
            --proof-bin     $HOME/zkconsent_setup/other/pghr13/zkmint/proof_zkmint.bin \
            --primary-bin   $HOME/zkconsent_setup/other/pghr13/zkmint/primary_zkmint.bin \
            --witness-bin   $HOME/zkconsent_setup/other/pghr13/zkmint/witness_zkmint.bin

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkconsent   -w ./samples/zkconsent.json \
            --extproof-json $HOME/zkconsent_setup/other/pghr13/zkcons/exproof_zkcons.json \
            --proof-bin $HOME/zkconsent_setup/other/pghr13/zkcons/proof_zkcons.bin \
            --primary-bin $HOME/zkconsent_setup/other/pghr13/zkcons/primary_zkcons.bin \
            --witness-bin $HOME/zkconsent_setup/other/pghr13/zkcons/witness_zkcons.bin

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkconfirm   -w ./samples/zkconfirm.json \
            --extproof-json $HOME/zkconsent_setup/other/pghr13/zkconf/exproof_zkconf.json \
            --proof-bin $HOME/zkconsent_setup/other/pghr13/zkconf/proof_zkconf.bin \
            --primary-bin $HOME/zkconsent_setup/other/pghr13/zkconf/primary_zkconf.bin \
            --witness-bin $HOME/zkconsent_setup/other/pghr13/zkconf/witness_zkconf.bin
