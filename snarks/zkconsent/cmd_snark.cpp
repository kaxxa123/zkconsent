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
#include "zksnarkstream.hpp"

using G16SnarkT  = libzeth::groth16_snark<libzkconsent::ppT>;
using P13SnarkT  = libzeth::pghr13_snark<libzkconsent::ppT>;
using G16StreamT = zkSnarkStream<libzkconsent::ppT, G16SnarkT>;
using P13StreamT = zkSnarkStream<libzkconsent::ppT, P13SnarkT>;

using namespace libzkconsent;

template<typename zkpT, typename SnarkT, typename ZKStreamT>
void ZKPSetup(
        const boost::filesystem::path &keypair_file,
        const boost::filesystem::path &pk_bin_file,
        const boost::filesystem::path &vk_bin_file,
        const boost::filesystem::path &vk_json_file, 
        const boost::filesystem::path &r1cs_json_file)
{
    zkpT aZkp;
    const typename SnarkT::keypair keys = aZkp.generate_trusted_setup();
    ZKStreamT::write_keypair(keys, keypair_file);
    ZKStreamT::write_proving_key(keys.pk, pk_bin_file);
    ZKStreamT::write_verification_key(keys.vk, vk_bin_file);
    ZKStreamT::write_verification_json(keys.vk, vk_json_file);
    write_constraint_system<zkpT>(aZkp, r1cs_json_file);
}

template<typename SnarkT, typename ZKStreamT>
void TrustedSetup(
        ZKCIRC type, 
        const boost::filesystem::path &keypair_file,
        const boost::filesystem::path &pk_bin_file,
        const boost::filesystem::path &vk_bin_file,
        const boost::filesystem::path &vk_json_file, 
        const boost::filesystem::path &r1cs_json_file)
{
    using zkterminateT  = zkterminate_wrap<ppT, FieldT, HashT, HashTreeT, SnarkT, ZKC_TreeDepth>;        
    using zkmintT       = zkmint_wrap<ppT, FieldT, HashT, HashTreeT, SnarkT, ZKC_TreeDepth>;        
    using zkconsentT    = zkconsent_wrap<ppT, FieldT, HashT, HashTreeT, SnarkT, ZKC_TreeDepth>;        
    using zkconfirmT    = zkconfirm_wrap<ppT, FieldT, HashT, HashTreeT, SnarkT, ZKC_TreeDepth>;        

    switch (type)
    {
    case ZK_TERMINATE:
        ZKPSetup<zkterminateT, SnarkT, ZKStreamT>(keypair_file, pk_bin_file, vk_bin_file, vk_json_file, r1cs_json_file);
        break;
    case ZK_MINT:
        ZKPSetup<zkmintT, SnarkT, ZKStreamT>(keypair_file, pk_bin_file, vk_bin_file, vk_json_file, r1cs_json_file);
        break;
    case ZK_CONSENT:
        ZKPSetup<zkconsentT, SnarkT, ZKStreamT>(keypair_file, pk_bin_file, vk_bin_file, vk_json_file, r1cs_json_file);
        break;
    case ZK_CONFIRM:
        ZKPSetup<zkconfirmT, SnarkT, ZKStreamT>(keypair_file, pk_bin_file, vk_bin_file, vk_json_file, r1cs_json_file);
        break;
    default:
        std::cerr << "FAILED: invalid ciruict name" << std::endl;
        break;
    }
}

void TrustedSetup(
    bool    bGroth16,
    ZKCIRC  type, 
    const boost::filesystem::path &keypair_file,
    const boost::filesystem::path &pk_bin_file,
    const boost::filesystem::path &vk_bin_file,
    const boost::filesystem::path &vk_json_file, 
    const boost::filesystem::path &r1cs_json_file)
{
    if (bGroth16)
        TrustedSetup<G16SnarkT, G16StreamT>(type, keypair_file, pk_bin_file, vk_bin_file, vk_json_file,  r1cs_json_file);
    else 
        TrustedSetup<P13SnarkT, P13StreamT>(type, keypair_file, pk_bin_file, vk_bin_file, vk_json_file,  r1cs_json_file);
}

template<typename jsonT, typename SnarkT, typename ZKStreamT>
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
                            ZKStreamT::load_keypair(keypair_file);

    if (bRunSetup) 
        ZKStreamT::write_keypair(keys, keypair_file);

    //Load proof parameters
    jsonT zkjson(witness_json_file);
    zkjson.trace();

    //Generate and dump proof data
    libzeth::extended_proof<ppT, SnarkT> ext_proof = 
        zkjson.prove_test(aZkp, keys.pk);

    ZKStreamT::write_extproof_to_json_file(ext_proof, exproof_json_file);
    ZKStreamT::write_proof_to_file(ext_proof.get_proof(), proof_bin_file);
    ZKStreamT::write_assignment_to_file(ext_proof.get_primary_inputs(), primary_bin_file);
    ZKStreamT::write_assignment_to_file(aZkp.get_last_assignment(), witness_bin_file);
}

template<typename SnarkT, typename ZKStreamT>
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
        ZKProve<zkterminate_json<SnarkT>, SnarkT, ZKStreamT>(
            keypair_file, witness_json_file, exproof_json_file, proof_bin_file, primary_bin_file ,witness_bin_file);
        break;
    case ZK_MINT:
        ZKProve<zkmint_json<SnarkT>, SnarkT, ZKStreamT>(
            keypair_file, witness_json_file, exproof_json_file, proof_bin_file, primary_bin_file ,witness_bin_file);
        break;
    case ZK_CONSENT:
        ZKProve<zkconsent_json<SnarkT>, SnarkT, ZKStreamT>(
            keypair_file, witness_json_file, exproof_json_file, proof_bin_file, primary_bin_file ,witness_bin_file);
        break;
    case ZK_CONFIRM:
        ZKProve<zkconfirm_json<SnarkT>, SnarkT, ZKStreamT>(
            keypair_file, witness_json_file, exproof_json_file, proof_bin_file, primary_bin_file ,witness_bin_file);
        break;
    default:
        std::cerr << "FAILED: invalid ciruict name" << std::endl;
        break;
    }
}

void GenerateProof(
    bool    bGroth16,
    ZKCIRC  type, 
    const boost::filesystem::path &keypair_file,
    const boost::filesystem::path &witness_json_file,
    const boost::filesystem::path &exproof_json_file,
    const boost::filesystem::path &proof_bin_file,
    const boost::filesystem::path &primary_bin_file,
    const boost::filesystem::path &witness_bin_file)
{
    if (bGroth16)
        GenerateProof<G16SnarkT, G16StreamT>(type, keypair_file,witness_json_file,exproof_json_file,proof_bin_file,primary_bin_file,witness_bin_file);
    else 
        GenerateProof<P13SnarkT, P13StreamT>(type, keypair_file,witness_json_file,exproof_json_file,proof_bin_file,primary_bin_file,witness_bin_file);
}

template<typename zkpT, typename SnarkT, typename ZKStreamT>
void ZKVerify(const boost::filesystem::path &keypair_file,
              const boost::filesystem::path &proof_bin_file,
              const boost::filesystem::path &primary_bin_file)
{
    zkpT aZkp;

    if (!boost::filesystem::exists(proof_bin_file))
    {
        std::cerr << "FAILED: Proof file not found: " << proof_bin_file << std::endl;
        return;
    }
    
    if (!boost::filesystem::exists(primary_bin_file))
    {
        std::cerr << "FAILED: Primary input file not found: " << primary_bin_file << std::endl;
        return;
    }

    //If the keypair file exists, load the keys, 
    //  otherwise create these
    bool bRunSetup = !boost::filesystem::exists(keypair_file);
    const typename SnarkT::keypair keys =  
                bRunSetup ? aZkp.generate_trusted_setup() :
                            ZKStreamT::load_keypair(keypair_file);

    if (bRunSetup) 
        ZKStreamT::write_keypair(keys, keypair_file);

    std::vector<FieldT>     primary_in  = ZKStreamT::load_assignment(primary_bin_file); 
    typename SnarkT::proof  proof       = ZKStreamT::load_proof(proof_bin_file);

    bool bVerify = SnarkT::verify(primary_in, proof, keys.vk);
    std::cout << std::endl;
    std::cout << "Proof Verification: " << (bVerify ? "OK" : "FAILED") << std::endl;
}

template<typename SnarkT, typename ZKStreamT>
void VerifyProof(
    ZKCIRC type, 
    const boost::filesystem::path &keypair_file,
    const boost::filesystem::path &proof_bin_file,
    const boost::filesystem::path &primary_bin_file)
{
    using zkterminateT  = zkterminate_wrap<ppT, FieldT, HashT, HashTreeT, SnarkT, ZKC_TreeDepth>;        
    using zkmintT       = zkmint_wrap<ppT, FieldT, HashT, HashTreeT, SnarkT, ZKC_TreeDepth>;        
    using zkconsentT    = zkconsent_wrap<ppT, FieldT, HashT, HashTreeT, SnarkT, ZKC_TreeDepth>;        
    using zkconfirmT    = zkconfirm_wrap<ppT, FieldT, HashT, HashTreeT, SnarkT, ZKC_TreeDepth>;        

    switch (type)
    {
    case ZK_TERMINATE:
        ZKVerify<zkterminateT, SnarkT, ZKStreamT>(keypair_file, proof_bin_file, primary_bin_file);
        break;
    case ZK_MINT:
        ZKVerify<zkmintT, SnarkT, ZKStreamT>(keypair_file, proof_bin_file, primary_bin_file);
        break;
    case ZK_CONSENT:
        ZKVerify<zkconsentT, SnarkT, ZKStreamT>(keypair_file, proof_bin_file, primary_bin_file);
        break;
    case ZK_CONFIRM:
        ZKVerify<zkconfirmT, SnarkT, ZKStreamT>(keypair_file, proof_bin_file, primary_bin_file);
        break;
    default:
        std::cerr << "FAILED: invalid ciruict name" << std::endl;
        break;
    }
}

void VerifyProof(
    bool    bGroth16,
    ZKCIRC  type, 
    const boost::filesystem::path &keypair_file,
    const boost::filesystem::path &proof_bin_file,
    const boost::filesystem::path &primary_bin_file)
{
    if (bGroth16)
        VerifyProof<G16SnarkT, G16StreamT>(type, keypair_file, proof_bin_file, primary_bin_file);            
    else 
        VerifyProof<P13SnarkT, P13StreamT>(type, keypair_file, proof_bin_file, primary_bin_file);            

}