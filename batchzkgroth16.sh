#!/usr/bin/bash

echo "======================================"
echo "Pre-Processing Groth16 Verifier params"
echo "======================================"

echo
python3 ./verifier/groth16_hlp/convertvk.py $HOME/zkconsent_setup/groth16/zkterm/vk_zkterm.json $HOME/zkconsent_setup/groth16/zkterm/vk_zkterm_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/zkterm/exproof_zkterm.json $HOME/zkconsent_setup/groth16/zkterm/exproof_zkterm_params.json
python3 ./verifier/groth16_hlp/convertvk.py $HOME/zkconsent_setup/groth16/zkmint/vk_zkmint.json $HOME/zkconsent_setup/groth16/zkmint/vk_zkmint_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/zkmint/exproof_zkmint.json $HOME/zkconsent_setup/groth16/zkmint/exproof_zkmint_params.json
python3 ./verifier/groth16_hlp/convertvk.py $HOME/zkconsent_setup/groth16/zkcons/vk_zkcons.json $HOME/zkconsent_setup/groth16/zkcons/vk_zkcons_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/zkcons/exproof_zkcons.json $HOME/zkconsent_setup/groth16/zkcons/exproof_zkcons_params.json
python3 ./verifier/groth16_hlp/convertvk.py $HOME/zkconsent_setup/groth16/zkconf/vk_zkconf.json $HOME/zkconsent_setup/groth16/zkconf/vk_zkconf_params.json
python3 ./verifier/groth16_hlp/convertproof.py $HOME/zkconsent_setup/groth16/zkconf/exproof_zkconf.json $HOME/zkconsent_setup/groth16/zkconf/exproof_zkconf_params.json

