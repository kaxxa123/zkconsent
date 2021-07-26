#!/usr/bin/bash

echo "========================================"
echo "Clearing temporary/build zkConsent files"
echo "========================================"
echo

echo
echo ">> Deleting SNARK build"
rm ./snarks/build -rf

echo
echo ">> Deleting zkconsentjs build"
node-gyp clean -C ./zkconsentjs
rm ./zkconsentjs/node_modules -rf

echo
echo ">> Deleting main build dir"
rm ./build -rf


echo
echo "Ready!"
echo

