#!/usr/bin/bash

echo "=================="
echo "Building zkConsent"
echo "=================="
echo ON

# git submodule update --init --recursive

cd ./snarks
mkdir build
cd build
cmake .
make -C ./build


echo "Ready!"

