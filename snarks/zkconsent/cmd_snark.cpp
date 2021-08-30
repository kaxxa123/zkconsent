#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <vector>

#include "libzeth/circuits/safe_arithmetic.hpp"
#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/circuits/prfs/prf.hpp"
#include "libzeth/core/utils.hpp"
#include "libzeth/core/field_element_utils.hpp"
#include "libzeth/zeth_constants.hpp"
#include "libzeth/snarks/groth16/groth16_snark.hpp"
#include "libzeth/core/extended_proof.hpp"

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

static void write_keypair(
    const typename SnarkT::keypair &keypair,
    const boost::filesystem::path &keypair_file)
{
    std::ofstream out_s(keypair_file.c_str(), std::ios_base::out | std::ios_base::binary);
    SnarkT::keypair_write_bytes(keypair, out_s);
}

static void write_proving_key(
    const typename SnarkT::proving_key &pk,
    const boost::filesystem::path &pk_file)
{
    std::ofstream out_s(
        pk_file.c_str(), std::ios_base::out | std::ios_base::binary);
    SnarkT::proving_key_write_bytes(pk, out_s);
}

static void write_verification_key(
    const typename SnarkT::verification_key &vk,
    const boost::filesystem::path &vk_file)
{
    std::ofstream out_s(
        vk_file.c_str(), std::ios_base::out | std::ios_base::binary);
    SnarkT::verification_key_write_bytes(vk, out_s);
}

template<typename zkpT>
static void write_constraint_system(
    const zkpT &prover, const boost::filesystem::path &r1cs_file)
{
#ifdef DEBUG
    std::ofstream r1cs_stream(r1cs_file.c_str());
    libzeth::r1cs_write_json(prover.get_constraint_system(), r1cs_stream);
#endif
}

static void write_extproof_to_json_file(
    const libzeth::extended_proof<ppT, SnarkT> &ext_proof,
    const boost::filesystem::path &proof_path)
{
    std::ofstream out_s(proof_path.c_str());
    ext_proof.write_json(out_s);
}

static void write_proof_to_file(
    const typename SnarkT::proof &proof,
    const boost::filesystem::path &proof_path)
{
    std::ofstream out_s(proof_path.c_str(), std::ios_base::out | std::ios_base::binary);
    SnarkT::proof_write_bytes(proof, out_s);
}

// static void write_assignment_to_file(
//     const std::vector<FieldT> &assignment,
//     const boost::filesystem::path &assignment_path)
// {
//     std::ofstream out_s(assignment_path.c_str(), std::ios_base::out | std::ios_base::binary);
//     libzeth::r1cs_variable_assignment_write_bytes(assignment, out_s);
// }

template<typename zkpT>
void ZKPSetup(
        const boost::filesystem::path &keypair_file,
        const boost::filesystem::path &pk_file,
        const boost::filesystem::path &vk_file,
        const boost::filesystem::path &r1cs_file)
{
    zkpT aZkp;
    const typename SnarkT::keypair keys = aZkp.generate_trusted_setup();
    write_keypair(keys, keypair_file);
    write_proving_key(keys.pk, pk_file);
    write_verification_key(keys.vk, vk_file);
    write_constraint_system<zkpT>(aZkp, r1cs_file);
}

void TrustedSetup(
        ZKCIRC type, 
        const boost::filesystem::path &keypair_file,
        const boost::filesystem::path &pk_file,
        const boost::filesystem::path &vk_file,
        const boost::filesystem::path &r1cs_file)
{
    switch (type)
    {
    case ZK_TERMINATE:
        ZKPSetup<zkterminateT>(keypair_file, pk_file, vk_file, r1cs_file);
        break;
    case ZK_MINT:
        ZKPSetup<zkmintT>(keypair_file, pk_file, vk_file, r1cs_file);
        break;
    case ZK_CONSENT:
        ZKPSetup<zkconsentT>(keypair_file, pk_file, vk_file, r1cs_file);
        break;
    case ZK_CONFIRM:
        ZKPSetup<zkconfirmT>(keypair_file, pk_file, vk_file, r1cs_file);
        break;
    default:
        std::cout << "FAILED: invalid ciruict name" << std::endl;
        break;
    }
}

template<typename zkpT>
void ZKProve(const boost::filesystem::path &keypair_file)
{
    bool    bRunSetup = !boost::filesystem::exists(keypair_file);
    zkpT    aZkp;

    const typename SnarkT::keypair keys =  
                bRunSetup ? aZkp.generate_trusted_setup() :
                            load_keypair(keypair_file);

    if (bRunSetup) 
        write_keypair(keys, keypair_file);
}

void GenerateProve(
    ZKCIRC type, 
    const boost::filesystem::path &keypair_file)
{
    switch (type)
    {
    case ZK_TERMINATE:
        ZKProve<zkterminateT>(keypair_file);
        break;
    case ZK_MINT:
        ZKProve<zkmintT>(keypair_file);
        break;
    case ZK_CONSENT:
        ZKProve<zkconsentT>(keypair_file);
        break;
    case ZK_CONFIRM:
        ZKProve<zkconfirmT>(keypair_file);
        break;
    default:
        std::cout << "FAILED: invalid ciruict name" << std::endl;
        break;
    }
}