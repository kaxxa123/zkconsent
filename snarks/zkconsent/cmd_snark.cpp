// SPDX-License-Identifier: LGPL-3.0+

#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <boost/filesystem.hpp>
#include <boost/json.hpp>

#include "libzeth/circuits/safe_arithmetic.hpp"
#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/circuits/prfs/prf.hpp"
#include "libzeth/core/utils.hpp"
#include "libzeth/core/field_element_utils.hpp"
#include "libzeth/zeth_constants.hpp"
#include "libzeth/snarks/groth16/groth16_snark.hpp"
#include "libzeth/snarks/pghr13/pghr13_snark.hpp"
#include "libzeth/core/extended_proof.hpp"
#include "libzeth/serialization/r1cs_variable_assignment_serialization.hpp"

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>

#include "zkc_params.hpp"
#include "zkc_helpers.hpp"
#include "extra_prf_gadgets.hpp"
#include "extra_cm_gadgets.hpp"
#include "extra_id_gadgets.hpp"
#include "extra_consent_gadgets.hpp"
#include "extra_study_gadgets.hpp"
#include "zkproof_terminate.hpp"
#include "zkproof_mint.hpp"
#include "zkproof_consent.hpp"
#include "zkproof_confirm.hpp"
#include "zkproof_wrap_hash.hpp"
#include "zkproof_wrap_simple.hpp"
#include "zkc_interface.hpp"

#include "clientdefs.hpp"
#include "zkjson.hpp"

// using SnarkT        = libzeth::groth16_snark<libzkconsent::ppT>;
using SnarkT        = libzeth::pghr13_snark<libzkconsent::ppT>;

using namespace libzkconsent;
using zkterminateT  = zkterminate_wrap<ppT, FieldT, HashT, HashTreeT, SnarkT, ZKC_TreeDepth>;        
using zkmintT       = zkmint_wrap<ppT, FieldT, HashT, HashTreeT, SnarkT, ZKC_TreeDepth>;        
using zkconsentT    = zkconsent_wrap<ppT, FieldT, HashT, HashTreeT, SnarkT, ZKC_TreeDepth>;        
using zkconfirmT    = zkconfirm_wrap<ppT, FieldT, HashT, HashTreeT, SnarkT, ZKC_TreeDepth>;        

static SnarkT::keypair load_keypair(
    const boost::filesystem::path &keypair_file)
{
    std::ifstream in_s(keypair_file.c_str(), std::ios_base::in | std::ios_base::binary);
    in_s.exceptions(std::ios_base::eofbit | std::ios_base::badbit | std::ios_base::failbit);

    SnarkT::keypair keypair;
    SnarkT::keypair_read_bytes(keypair, in_s);
    return keypair;
}

static SnarkT::proof load_proof(
    const boost::filesystem::path &proof_path)
{
    std::ifstream in_s(proof_path.c_str(), std::ios_base::in | std::ios_base::binary);
    in_s.exceptions(std::ios_base::eofbit | std::ios_base::badbit | std::ios_base::failbit);

    SnarkT::proof proof;
    SnarkT::proof_read_bytes(proof, in_s);
    return proof;
}

static std::vector<FieldT> load_assignment(
    const boost::filesystem::path &assignment_path)
{
    std::ifstream in_s(assignment_path.c_str(), std::ios_base::in | std::ios_base::binary);
    in_s.exceptions(std::ios_base::eofbit | std::ios_base::badbit | std::ios_base::failbit);

    std::vector<FieldT> assignment;
    libzeth::r1cs_variable_assignment_read_bytes(assignment, in_s);
    return assignment;
}

static void write_keypair(
    const typename SnarkT::keypair &keypair,
    const boost::filesystem::path &keypair_file)
{
    std::ofstream out_s(keypair_file.c_str(), std::ios_base::out | std::ios_base::binary);
    SnarkT::keypair_write_bytes(keypair, out_s);
}

static void write_proving_key(
    const typename SnarkT::proving_key &pk,
    const boost::filesystem::path &pk_bin_file)
{
    std::ofstream out_s(
        pk_bin_file.c_str(), std::ios_base::out | std::ios_base::binary);
    SnarkT::proving_key_write_bytes(pk, out_s);
}

static void write_verification_key(
    const typename SnarkT::verification_key &vk,
    const boost::filesystem::path &vk_bin_file)
{
    std::ofstream out_s(
        vk_bin_file.c_str(), std::ios_base::out | std::ios_base::binary);
    SnarkT::verification_key_write_bytes(vk, out_s);
}

static void write_verification_json(
    const typename SnarkT::verification_key &vk,
    const boost::filesystem::path &vk_json_file)
{
    std::ofstream out_s(vk_json_file.c_str(), std::ios_base::out);
    SnarkT::verification_key_write_json(vk, out_s);
}

template<typename zkpT>
static void write_constraint_system(
    const zkpT &prover, const boost::filesystem::path &r1cs_json_file)
{
#ifdef DEBUG
    std::ofstream r1cs_stream(r1cs_json_file.c_str(), std::ios_base::out);
    libzeth::r1cs_write_json(prover.get_constraint_system(), r1cs_stream);
#endif
}

static void write_extproof_to_json_file(
    const libzeth::extended_proof<ppT, SnarkT> &ext_proof,
    const boost::filesystem::path &proof_path)
{
    std::ofstream out_s(proof_path.c_str(), std::ios_base::out);
    ext_proof.write_json(out_s);
}

static void write_proof_to_file(
    const typename SnarkT::proof &proof,
    const boost::filesystem::path &proof_path)
{
    std::ofstream out_s(proof_path.c_str(), std::ios_base::out | std::ios_base::binary);
    SnarkT::proof_write_bytes(proof, out_s);
}

static void write_assignment_to_file(
    const std::vector<FieldT> &assignment,
    const boost::filesystem::path &assignment_path)
{
    std::ofstream out_s(assignment_path.c_str(), std::ios_base::out | std::ios_base::binary);
    libzeth::r1cs_variable_assignment_write_bytes(assignment, out_s);
}

template<typename zkpT>
void ZKPSetup(
        const boost::filesystem::path &keypair_file,
        const boost::filesystem::path &pk_bin_file,
        const boost::filesystem::path &vk_bin_file,
        const boost::filesystem::path &vk_json_file, 
        const boost::filesystem::path &r1cs_json_file)
{
    zkpT aZkp;
    const typename SnarkT::keypair keys = aZkp.generate_trusted_setup();
    write_keypair(keys, keypair_file);
    write_proving_key(keys.pk, pk_bin_file);
    write_verification_key(keys.vk, vk_bin_file);
    write_verification_json(keys.vk, vk_json_file);
    write_constraint_system<zkpT>(aZkp, r1cs_json_file);
}

void TrustedSetup(
        ZKCIRC type, 
        const boost::filesystem::path &keypair_file,
        const boost::filesystem::path &pk_bin_file,
        const boost::filesystem::path &vk_bin_file,
        const boost::filesystem::path &vk_json_file, 
        const boost::filesystem::path &r1cs_json_file)
{
    switch (type)
    {
    case ZK_TERMINATE:
        ZKPSetup<zkterminateT>(keypair_file, pk_bin_file, vk_bin_file, vk_json_file, r1cs_json_file);
        break;
    case ZK_MINT:
        ZKPSetup<zkmintT>(keypair_file, pk_bin_file, vk_bin_file, vk_json_file, r1cs_json_file);
        break;
    case ZK_CONSENT:
        ZKPSetup<zkconsentT>(keypair_file, pk_bin_file, vk_bin_file, vk_json_file, r1cs_json_file);
        break;
    case ZK_CONFIRM:
        ZKPSetup<zkconfirmT>(keypair_file, pk_bin_file, vk_bin_file, vk_json_file, r1cs_json_file);
        break;
    default:
        std::cout << "FAILED: invalid ciruict name" << std::endl;
        break;
    }
}

template<typename jsonT>
void ZKProve(const boost::filesystem::path &keypair_file,
             const boost::filesystem::path &witness_json_file,
             const boost::filesystem::path &exproof_json_file,
             const boost::filesystem::path &proof_bin_file,
             const boost::filesystem::path &primary_bin_file,
             const boost::filesystem::path &witness_bin_file)
{
    typename jsonT::circuitT aZkp;

    //If the keypair file exists, load the keys, 
    //  otherwise create these
    bool bRunSetup = !boost::filesystem::exists(keypair_file);
    const typename SnarkT::keypair keys =  
                bRunSetup ? aZkp.generate_trusted_setup() :
                            load_keypair(keypair_file);

    if (bRunSetup) 
        write_keypair(keys, keypair_file);

    //Load proof parameters
    jsonT zkjson(witness_json_file);
    zkjson.trace();

    //Generate and dump proof data
    libzeth::extended_proof<ppT, SnarkT> ext_proof = 
        zkjson.prove_test(aZkp, keys.pk);

    write_extproof_to_json_file(ext_proof, exproof_json_file);
    write_proof_to_file(ext_proof.get_proof(), proof_bin_file);
    write_assignment_to_file(ext_proof.get_primary_inputs(), primary_bin_file);
    write_assignment_to_file(aZkp.get_last_assignment(), witness_bin_file);
}

void GenerateProof(
    ZKCIRC type, 
    const boost::filesystem::path &keypair_file,
    const boost::filesystem::path &witness_json_file,
    const boost::filesystem::path &exproof_json_file,
    const boost::filesystem::path &proof_bin_file,
    const boost::filesystem::path &primary_bin_file,
    const boost::filesystem::path &witness_bin_file)
{
    switch (type)
    {
    case ZK_TERMINATE:
        ZKProve<zkterminate_json<SnarkT>>(
            keypair_file, witness_json_file, exproof_json_file, proof_bin_file, primary_bin_file ,witness_bin_file);
        break;
    case ZK_MINT:
        ZKProve<zkmint_json<SnarkT>>(
            keypair_file, witness_json_file, exproof_json_file, proof_bin_file, primary_bin_file ,witness_bin_file);
        break;
    case ZK_CONSENT:
        ZKProve<zkconsent_json<SnarkT>>(
            keypair_file, witness_json_file, exproof_json_file, proof_bin_file, primary_bin_file ,witness_bin_file);
        break;
    case ZK_CONFIRM:
        ZKProve<zkconfirm_json<SnarkT>>(
            keypair_file, witness_json_file, exproof_json_file, proof_bin_file, primary_bin_file ,witness_bin_file);
        break;
    default:
        std::cout << "FAILED: invalid ciruict name" << std::endl;
        break;
    }
}

template<typename zkpT>
void ZKVerify(const boost::filesystem::path &keypair_file,
             const boost::filesystem::path &proof_bin_file,
             const boost::filesystem::path &primary_bin_file)
{
    zkpT aZkp;

    if (!boost::filesystem::exists(proof_bin_file))
    {
        std::cout << "FAILED: Proof file not found: " << proof_bin_file << std::endl;
        return;
    }
    
    if (!boost::filesystem::exists(primary_bin_file))
    {
        std::cout << "FAILED: Primary input file not found: " << primary_bin_file << std::endl;
        return;
    }

    //If the keypair file exists, load the keys, 
    //  otherwise create these
    bool bRunSetup = !boost::filesystem::exists(keypair_file);
    const typename SnarkT::keypair keys =  
                bRunSetup ? aZkp.generate_trusted_setup() :
                            load_keypair(keypair_file);

    if (bRunSetup) 
        write_keypair(keys, keypair_file);

    std::vector<FieldT> primary_in  = load_assignment(primary_bin_file); 
    SnarkT::proof       proof       = load_proof(proof_bin_file);

    bool bVerify = SnarkT::verify(primary_in, proof, keys.vk);
    std::cout << std::endl;
    std::cout << "Proof Verification: " << (bVerify ? "OK" : "FAILED") << std::endl;
}

void VerifyProof(
    ZKCIRC type, 
    const boost::filesystem::path &keypair_file,
    const boost::filesystem::path &proof_bin_file,
    const boost::filesystem::path &primary_bin_file)
{
    switch (type)
    {
    case ZK_TERMINATE:
        ZKVerify<zkterminateT>(keypair_file, proof_bin_file, primary_bin_file);
        break;
    case ZK_MINT:
        ZKVerify<zkmintT>(keypair_file, proof_bin_file, primary_bin_file);
        break;
    case ZK_CONSENT:
        ZKVerify<zkconsentT>(keypair_file, proof_bin_file, primary_bin_file);
        break;
    case ZK_CONFIRM:
        ZKVerify<zkconfirmT>(keypair_file, proof_bin_file, primary_bin_file);
        break;
    default:
        std::cout << "FAILED: invalid ciruict name" << std::endl;
        break;
    }
}
