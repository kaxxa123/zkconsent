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
echo ">> Building nodegw"
npm i --prefix ./nodegw
# node-gyp rebuild -C ./nodegw

echo
echo "Ready!"
echo

