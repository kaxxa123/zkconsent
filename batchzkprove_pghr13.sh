#!/usr/bin/bash

echo "=================================="
echo "Generating PGHR13 Proofs zkConsent"
echo "=================================="

mkdir -p $HOME/zkconsent_logs/pghr13

echo
echo ">> SNARKs Prove"
./snarks/build/zkconsent/zkconsent prove --pghr13 --zkterminate     -w ./samples/zkterminate.json \
            | tee $HOME/zkconsent_logs/pghr13/zkterm_proof.log

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkmint          -w ./samples/zkmint.json \
            | tee $HOME/zkconsent_logs/pghr13/zkmint_proof.log

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkconsent       -w ./samples/zkconsent.json \
            | tee $HOME/zkconsent_logs/pghr13/zkcons_proof.log

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkconfconsent   -w ./samples/zkconfconsent.json \
            | tee $HOME/zkconsent_logs/pghr13/zkconsconf_proof.log

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkconfterminate -w ./samples/zkconfterminate.json \
            | tee $HOME/zkconsent_logs/pghr13/zktermconf_proof.log

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkterminatesimp -w ./samples/zkterminate.json \
            | tee $HOME/zkconsent_logs/pghr13/zksimpterm_proof.log

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkmintsimp      -w ./samples/zkmint.json \
            | tee $HOME/zkconsent_logs/pghr13/zksimpmint_proof.log

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkconsentsimp   -w ./samples/zkconsent.json \
            | tee $HOME/zkconsent_logs/pghr13/zksimpcons_proof.log


./snarks/build/zkconsent/zkconsent prove --pghr13 --zkterminate -w ./samples/zkterminate_other.json \
            --extproof-json $HOME/zkconsent_setup/pghr13/other/zkterm/exproof_zkterm.json \
            --proof-bin     $HOME/zkconsent_setup/pghr13/other/zkterm/proof_zkterm.bin \
            --primary-bin   $HOME/zkconsent_setup/pghr13/other/zkterm/primary_zkterm.bin \
            --witness-bin   $HOME/zkconsent_setup/pghr13/other/zkterm/witness_zkterm.bin \
            | tee $HOME/zkconsent_logs/pghr13/zkterm_proofother.log

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkmint      -w ./samples/zkmint_other.json \
            --extproof-json $HOME/zkconsent_setup/pghr13/other/zkmint/exproof_zkmint.json \
            --proof-bin     $HOME/zkconsent_setup/pghr13/other/zkmint/proof_zkmint.bin \
            --primary-bin   $HOME/zkconsent_setup/pghr13/other/zkmint/primary_zkmint.bin \
            --witness-bin   $HOME/zkconsent_setup/pghr13/other/zkmint/witness_zkmint.bin \
            | tee $HOME/zkconsent_logs/pghr13/zkmint_proofother.log

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkconsent   -w ./samples/zkconsent_other.json \
            --extproof-json $HOME/zkconsent_setup/pghr13/other/zkcons/exproof_zkcons.json \
            --proof-bin     $HOME/zkconsent_setup/pghr13/other/zkcons/proof_zkcons.bin \
            --primary-bin   $HOME/zkconsent_setup/pghr13/other/zkcons/primary_zkcons.bin \
            --witness-bin   $HOME/zkconsent_setup/pghr13/other/zkcons/witness_zkcons.bin \
            | tee $HOME/zkconsent_logs/pghr13/zkcons_proofother.log

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkconfconsent   -w ./samples/zkconfconsent_other.json \
            --extproof-json $HOME/zkconsent_setup/pghr13/other/zkconfcons/exproof_zkconfcons.json \
            --proof-bin     $HOME/zkconsent_setup/pghr13/other/zkconfcons/proof_zkconfcons.bin \
            --primary-bin   $HOME/zkconsent_setup/pghr13/other/zkconfcons/primary_zkconfcons.bin \
            --witness-bin   $HOME/zkconsent_setup/pghr13/other/zkconfcons/witness_zkconfcons.bin \
            | tee $HOME/zkconsent_logs/pghr13/zkconsconf_proofother.log

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkconfterminate -w ./samples/zkconfterminate_other.json \
            --extproof-json $HOME/zkconsent_setup/pghr13/other/zkconfterm/exproof_zkconfterm.json \
            --proof-bin     $HOME/zkconsent_setup/pghr13/other/zkconfterm/proof_zkconfterm.bin \
            --primary-bin   $HOME/zkconsent_setup/pghr13/other/zkconfterm/primary_zkconfterm.bin \
            --witness-bin   $HOME/zkconsent_setup/pghr13/other/zkconfterm/witness_zkconfterm.bin \
            | tee $HOME/zkconsent_logs/pghr13/zktermconf_proofother.log

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkterminatesimp -w ./samples/zkterminate_other.json \
            --extproof-json $HOME/zkconsent_setup/pghr13/other/zksimpterm/exproof_zksimpterm.json \
            --proof-bin     $HOME/zkconsent_setup/pghr13/other/zksimpterm/proof_zksimpterm.bin \
            --primary-bin   $HOME/zkconsent_setup/pghr13/other/zksimpterm/primary_zksimpterm.bin \
            --witness-bin   $HOME/zkconsent_setup/pghr13/other/zksimpterm/witness_zksimpterm.bin \
            | tee $HOME/zkconsent_logs/pghr13/zksimpterm_proofother.log

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkmintsimp      -w ./samples/zkmint_other.json \
            --extproof-json $HOME/zkconsent_setup/pghr13/other/zksimpmint/exproof_zksimpmint.json  \
            --proof-bin     $HOME/zkconsent_setup/pghr13/other/zksimpmint/proof_zksimpmint.bin \
            --primary-bin   $HOME/zkconsent_setup/pghr13/other/zksimpmint/primary_zksimpmint.bin \
            --witness-bin   $HOME/zkconsent_setup/pghr13/other/zksimpmint/witness_zksimpmint.bin \
            | tee $HOME/zkconsent_logs/pghr13/zksimpmint_proofother.log

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkconsentsimp   -w ./samples/zkconsent_other.json \
            --extproof-json $HOME/zkconsent_setup/pghr13/other/zksimpcons/exproof_zksimpcons.json \
            --proof-bin     $HOME/zkconsent_setup/pghr13/other/zksimpcons/proof_zksimpcons.bin \
            --primary-bin   $HOME/zkconsent_setup/pghr13/other/zksimpcons/primary_zksimpcons.bin \
            --witness-bin   $HOME/zkconsent_setup/pghr13/other/zksimpcons/witness_zksimpcons.bin \
            | tee $HOME/zkconsent_logs/pghr13/zksimpcons_proofother.log

