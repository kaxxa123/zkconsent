#!/usr/bin/bash

echo "=================================="
echo "Generating Groth16 Setup zkConsent"
echo "=================================="

echo
echo ">> Cleanup setup dir"
rm ~/zkconsent_setup/groth16/* -rf

echo
echo ">> SNARKs Setup"
./snarks/build/zkconsent/zkconsent setup --groth16 --zkterminate
./snarks/build/zkconsent/zkconsent setup --groth16 --zkmint
./snarks/build/zkconsent/zkconsent setup --groth16 --zkconsent
./snarks/build/zkconsent/zkconsent setup --groth16 --zkconfconsent
