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

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkterminate -w ./samples/zkterminate_other.json \
            --extproof-json $HOME/zkconsent_setup/pghr13/other/zkterm/exproof_zkterm.json \
            --proof-bin     $HOME/zkconsent_setup/pghr13/other/zkterm/proof_zkterm.bin \
            --primary-bin   $HOME/zkconsent_setup/pghr13/other/zkterm/primary_zkterm.bin \
            --witness-bin   $HOME/zkconsent_setup/pghr13/other/zkterm/witness_zkterm.bin

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkmint      -w ./samples/zkmint_other.json \
            --extproof-json $HOME/zkconsent_setup/pghr13/other/zkmint/exproof_zkmint.json \
            --proof-bin     $HOME/zkconsent_setup/pghr13/other/zkmint/proof_zkmint.bin \
            --primary-bin   $HOME/zkconsent_setup/pghr13/other/zkmint/primary_zkmint.bin \
            --witness-bin   $HOME/zkconsent_setup/pghr13/other/zkmint/witness_zkmint.bin

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkconsent   -w ./samples/zkconsent_other.json \
            --extproof-json $HOME/zkconsent_setup/pghr13/other/zkcons/exproof_zkcons.json \
            --proof-bin     $HOME/zkconsent_setup/pghr13/other/zkcons/proof_zkcons.bin \
            --primary-bin   $HOME/zkconsent_setup/pghr13/other/zkcons/primary_zkcons.bin \
            --witness-bin   $HOME/zkconsent_setup/pghr13/other/zkcons/witness_zkcons.bin

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkconfirm   -w ./samples/zkconfirm_other.json \
            --extproof-json $HOME/zkconsent_setup/pghr13/other/zkconf/exproof_zkconf.json \
            --proof-bin     $HOME/zkconsent_setup/pghr13/other/zkconf/proof_zkconf.bin \
            --primary-bin   $HOME/zkconsent_setup/pghr13/other/zkconf/primary_zkconf.bin \
            --witness-bin   $HOME/zkconsent_setup/pghr13/other/zkconf/witness_zkconf.bin
