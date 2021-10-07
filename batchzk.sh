#!/usr/bin/bash

echo "================================="
echo "Generating Setup zkConsent"
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
