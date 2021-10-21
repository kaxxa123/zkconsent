#!/usr/bin/bash

echo "================================="
echo "Generating PGHR13 Setup zkConsent"
echo "================================="

echo
echo ">> Cleanup setup dir"
mkdir -p $HOME/zkconsent_setup/pghr13
mkdir -p $HOME/zkconsent_logs/pghr13
rm ~/zkconsent_setup/pghr13/* -rf
rm ~/zkconsent_logs/pghr13/* -rf

echo
echo ">> SNARKs Setup"
./snarks/build/zkconsent/zkconsent setup --pghr13 --zkterminate         | tee $HOME/zkconsent_logs/pghr13/zkterm_setup.log
./snarks/build/zkconsent/zkconsent setup --pghr13 --zkmint              | tee $HOME/zkconsent_logs/pghr13/zkmint_setup.log
./snarks/build/zkconsent/zkconsent setup --pghr13 --zkconsent           | tee $HOME/zkconsent_logs/pghr13/zkcons_setup.log
./snarks/build/zkconsent/zkconsent setup --pghr13 --zkconfconsent       | tee $HOME/zkconsent_logs/pghr13/zkconsconf_setup.log
./snarks/build/zkconsent/zkconsent setup --pghr13 --zkconfterminate     | tee $HOME/zkconsent_logs/pghr13/zktermconf_setup.log
