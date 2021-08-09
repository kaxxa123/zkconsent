#ifndef __ZKC_PARAMS_H_
#define __ZKC_PARAMS_H_

namespace libzkconsent
{

using pp            = libff::alt_bn128_pp;
using FieldT        = libff::Fr<pp>;
using HashT         = libzeth::HashT<FieldT>;
using HashTreeT     = libzeth::HashTreeT<FieldT>;
using InputHasherT  = libzeth::mimc_input_hasher<FieldT, HashTreeT>;

using PKT           = libsnark::r1cs_gg_ppzksnark_proving_key<pp>;
using VKT           = libsnark::r1cs_gg_ppzksnark_verification_key<pp>;
using KeypairT      = libsnark::r1cs_gg_ppzksnark_keypair<pp>;
using ProofT        = libsnark::r1cs_gg_ppzksnark_proof<pp>;

const size_t ZKC_TreeDepth      = libzeth::ZETH_MERKLE_TREE_DEPTH;
const size_t ZKC_STUDYID_SIZE   = libzeth::ZETH_V_SIZE;
const size_t ZKC_CHOICE_SIZE    = 8;


}

#endif //__ZKC_PARAMS_H_
