#!/usr/bin/bash

echo "=================================="
echo "Generating Groth16 Setup zkConsent"
echo "=================================="

echo
echo ">> Cleanup setup dir"
mkdir -p $HOME/zkconsent_setup/groth16
mkdir -p $HOME/zkconsent_logs/groth16
rm ~/zkconsent_setup/groth16/* -rf
rm ~/zkconsent_logs/groth16/* -rf

echo
echo ">> SNARKs Setup"
./snarks/build/zkconsent/zkconsent setup --groth16 --zkterminate      | tee $HOME/zkconsent_logs/groth16/zkterm_setup.log
./snarks/build/zkconsent/zkconsent setup --groth16 --zkmint           | tee $HOME/zkconsent_logs/groth16/zkmint_setup.log
./snarks/build/zkconsent/zkconsent setup --groth16 --zkconsent        | tee $HOME/zkconsent_logs/groth16/zkcons_setup.log
./snarks/build/zkconsent/zkconsent setup --groth16 --zkconfconsent    | tee $HOME/zkconsent_logs/groth16/zkconsconf_setup.log
./snarks/build/zkconsent/zkconsent setup --groth16 --zkconfterminate  | tee $HOME/zkconsent_logs/groth16/zktermconf_setup.log
