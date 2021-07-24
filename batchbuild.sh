#!/usr/bin/bash

echo "=================="
echo "Building zkConsent"
echo "=================="


echo
echo ">> Building SNARKs"
mkdir ./build
mkdir ./snarks/build
cmake -S ./snarks -B ./snarks/build
make -C  ./snarks/build
cp ./snarks/build/snarkhlp/libsnarkhlp.a  ./build
cp ./snarks/build/test/MYSNARK  ./build

echo
echo "Ready!"
echo

