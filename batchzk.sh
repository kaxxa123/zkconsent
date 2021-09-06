#!/usr/bin/bash

echo "================================="
echo "Generating Setup/Proofs zkConsent"
echo "================================="

echo
echo ">> Cleanup setup dir"
rm ~/zkconsent_setup/* -rf

echo
echo ">> SNARKs Setup"
./snarks/build/zkconsent/zkconsent setup --zkterminate
./snarks/build/zkconsent/zkconsent setup --zkmint
./snarks/build/zkconsent/zkconsent setup --zkconsent
./snarks/build/zkconsent/zkconsent setup --zkconfirm

echo
echo ">> SNARKs Prove"
./snarks/build/zkconsent/zkconsent prove --zkterminate -w ./samples/zkterminate.json
./snarks/build/zkconsent/zkconsent prove --zkmint      -w ./samples/zkmint.json
./snarks/build/zkconsent/zkconsent prove --zkconsent   -w ./samples/zkconsent.json
./snarks/build/zkconsent/zkconsent prove --zkconfirm   -w ./samples/zkconfirm.json
