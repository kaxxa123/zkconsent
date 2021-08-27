#ifndef __ZKC_PARAMS_H_
#define __ZKC_PARAMS_H_

namespace libzkconsent
{

using ppT           = libff::alt_bn128_pp;
using FieldT        = libff::Fr<ppT>;
using HashT         = libzeth::HashT<FieldT>;
using HashTreeT     = libzeth::HashTreeT<FieldT>;

// using InputHasherT  = libzeth::mimc_input_hasher<FieldT, HashTreeT>;
// using PKT           = libsnark::r1cs_gg_ppzksnark_proving_key<ppT>;
// using VKT           = libsnark::r1cs_gg_ppzksnark_verification_key<ppT>;
// using KeypairT      = libsnark::r1cs_gg_ppzksnark_keypair<ppT>;
// using ProofT        = libsnark::r1cs_gg_ppzksnark_proof<ppT>;

///home/alex/zkconsent/snarks/depends/zeth/zeth_config.h.in
///home/alex/zkconsent/snarks/depends/zeth/libzeth/snarks/groth16/groth16_snark.hpp
using SnarkT        = libzeth::groth16_snark<ppT>;
// using APIHandlerT   = groth16_api_handler<ppT>;


const size_t ZKC_TreeDepth      = libzeth::ZETH_MERKLE_TREE_DEPTH;
const size_t ZKC_STUDYID_SIZE   = libzeth::ZETH_V_SIZE;
const size_t ZKC_CHOICE_SIZE    = 8;


}

#endif //__ZKC_PARAMS_H_
