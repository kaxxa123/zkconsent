# zkConsent

This repository includes the code developed for the dissertation titled:

__Privacy-Preserving Solutions for Decentralized Permissionless Blockchains__

A dissertation submitted in partial fulfilment of the requirements for the degree of M.Sc. in Blockchain and DLTs, University of Malta.

This code started off from a [fork of the Zeth project](https://github.com/clearmatics/zeth/tree/8247fc3df9d0025000196293e121330440178ec0) from Clearmatics. Based on this the ZKPs for the consent system presented in this dissertation were developed.

<br />

 ---

## Setup
| | |
|----|----------|
|Platform |Ubuntu 20.04 LTS|
|Node.js | 12.22.1| 
|Truffle| 5.4.17| 
|Web3.js| 1.5.3|
|Boost| 1.77.0|
| | |

<br />

__libsnark dependency installation__
```BASH
sudo apt install build-essential cmake git libgmp3-dev libprocps-dev \
                   python3-markdown libboost-program-options-dev \
                   libssl-dev python3 pkg-config
```

For more details on libsnark dependencies refer to:

[libsnark: a C++ library for zkSNARK proofs](https://github.com/scipr-lab/libsnark)

[libsnark-tutorial by Howard Wu](https://github.com/howardwu/libsnark-tutorial)

[libsnark tutorial by Christian Lundkvist and Sam Mayo](https://github.com/christianlundkvist/libsnark-tutorial)


<br />

__Compiler Installation__
```BASH
sudo apt install gcc-10 g++-10
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-10 100 \
            --slave /usr/bin/g++ g++ /usr/bin/g++-10 --slave /usr/bin/gcov gcov /usr/bin/gcov-10
```

<br />

---

## Code Structure
This section describes the repository structure.

<br />

### ZKP Trusted Setup and Proof Generation

| Folder | Description                                          |
|--------|------------------------------------------------------|
|./snarks  | Root folder containing the implementation of libsnark based ZKPs.  |
|./snarks/depends  | Git module dependencies for the zkconsenthlp library.  |
|./snarks/zkconsenthlp  |  A C++ libsnark library implementing the five ZKPs required by the consent system. |
|./snarks/zkconsent  | A C++ command-line tool wrapping the zkconsenthlp library for running the trusted setup and generating proofs. |

<br />

### ZKP Verifiers

| Folder | Description                                          |
|--------|------------------------------------------------------|
|./verifier | Root folder for ZKP verifier implementations. |
|./verifier/groth16_hlp | Python scripts for pre-processing Groth16 proofs returned by the zkconsent command-line tool. This pre-processing is necessary for submitting the Groth16 proofs to the on-chain verifier smart contracts. |
|./verifier/verifier_contract | Solidity verifier smart contracts for Groth16 and PGHR13 ZKP schemes. |

<br />

### Miscellaneous 

| Folder | Description                                          |
|--------|------------------------------------------------------|
|./eth-gas | A node.js project for retrieving Ethereum Gas fees. This command-line tool takes as input a block range and returns the gas fees paid for each transaction. |
|./samples | A set of json files containing sample ZKP witnesses that may be used for test generation of proofs. |
|./tests/blake2s | A node.js project for computing commitments using an independent implementation of Blake2s. |
|./zeth_tests | Raw data obtained from tests ran against Zeth. |
|./zkconsentjs | Initial implementation of a C library for allowing integration of the zkconsenthlp library into node.js projects. |



<!-- | Folder | Description                                          |
|--------|------------------------------------------------------|
|./eth-gas | A node.js project for retrieving Ethereum Gas fees. This command-line tool takes as input a block range and returns the gas fees paid for each transaction. |
|./samples | A set of json files containing sample ZKP witnesses that may be used for test generation of proofs. |
|./snarks  | Root folder containing the implementation of libsnark based ZKPs.  |
|./snarks/depends  | Git module dependencies for the zkconsenthlp library.  |
|./snarks/zkconsenthlp  |  A C++ libsnark library implementing the five ZKPs required by the consent system. |
|./snarks/zkconsent  | A C++ command-line tool wrapping the zkconsenthlp library for running the trusted setup and generating proofs. |
|./tests/blake2s | A node.js project for computing commitments using an independent implementation of Blake2s. |
|./verifier | Root folder for ZKP verifier implementations. |
|./verifier/groth16_hlp | Python scripts for pre-processing Groth16 proofs returned by the zkconsent command-line tool. This pre-processing is necessary for submitting the Groth16 proofs to the on-chain verifier smart contracts. |
|./verifier/verifier_contract | Solidity verifier smart contracts for Groth16 and PGHR13 ZKP schemes. |
|./zeth_tests | Raw data obtained from tests ran against Zeth. |
|./zkconsentjs | Initial implementation of a C library for allowing integration of the zkconsenthlp library into node.js projects. | -->
