#!/usr/bin/bash

echo "=================="
echo "Building zkConsent"
echo "=================="

mkdir ./snarks/build

echo
echo ">> Building SNARKs"
cmake -S ./snarks -B ./snarks/build
make -C  ./snarks/build
sudo make install -C  ./snarks/build

echo
echo ">> Building zkconsentjs"
npm i --prefix ./zkconsentjs
# node-gyp rebuild -C ./zkconsentjs

echo
echo "Ready!"
echo

