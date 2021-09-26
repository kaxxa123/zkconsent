#!/usr/bin/bash

echo "================================="
echo "Generating Setup/Proofs zkConsent"
echo "================================="

echo
echo ">> Cleanup setup dir"
rm ~/zkconsent_setup/* -rf

echo
echo ">> SNARKs Setup"
./snarks/build/zkconsent/zkconsent setup --groth16 --zkterminate
./snarks/build/zkconsent/zkconsent setup --groth16 --zkmint
./snarks/build/zkconsent/zkconsent setup --groth16 --zkconsent
./snarks/build/zkconsent/zkconsent setup --groth16 --zkconfirm

./snarks/build/zkconsent/zkconsent setup --pghr13 --zkterminate
./snarks/build/zkconsent/zkconsent setup --pghr13 --zkmint
./snarks/build/zkconsent/zkconsent setup --pghr13 --zkconsent
./snarks/build/zkconsent/zkconsent setup --pghr13 --zkconfirm

echo
echo ">> SNARKs Prove"
./snarks/build/zkconsent/zkconsent prove --groth16 --zkterminate -w ./samples/zkterminate.json
./snarks/build/zkconsent/zkconsent prove --groth16 --zkmint      -w ./samples/zkmint.json
./snarks/build/zkconsent/zkconsent prove --groth16 --zkconsent   -w ./samples/zkconsent.json
./snarks/build/zkconsent/zkconsent prove --groth16 --zkconfirm   -w ./samples/zkconfirm.json

./snarks/build/zkconsent/zkconsent prove --pghr13 --zkterminate -w ./samples/zkterminate.json
./snarks/build/zkconsent/zkconsent prove --pghr13 --zkmint      -w ./samples/zkmint.json
./snarks/build/zkconsent/zkconsent prove --pghr13 --zkconsent   -w ./samples/zkconsent.json
./snarks/build/zkconsent/zkconsent prove --pghr13 --zkconfirm   -w ./samples/zkconfirm.json
