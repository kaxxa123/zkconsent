#!/usr/bin/bash

echo "========================================"
echo "Clearing temporary/build zkConsent files"
echo "========================================"
echo

echo
echo ">> Deleting SNARK build dir"
rm ./snarks/build -rf

echo
echo ">> Deleting main build dir"
rm ./build -rf


echo
echo "Ready!"
echo

