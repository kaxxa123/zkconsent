#!/usr/bin/bash

echo "=================="
echo "Building zkConsent"
echo "=================="

mkdir -p ./build/bin
mkdir    ./build/include
mkdir ./snarks/build

echo
echo ">> Building SNARKs"
cmake -S ./snarks -B ./snarks/build
make -C  ./snarks/build
sudo make install -C  ./snarks/build

cp ./snarks/build/snarkhlp/libsnarkhlp.so   ./build/bin
cp ./snarks/build/test/MYSNARK              ./build/bin
cp ./snarks/snarkhlp/prfxxx.hpp             ./build/include

echo
echo ">> Building nodegw"
node-gyp rebuild -C ./nodegw

cp ./nodegw/build/Release/nodegw.node       ./build/bin

echo
echo "Ready!"
echo

