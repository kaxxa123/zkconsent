#ifndef __ZKC_PARAMS_H_
#define __ZKC_PARAMS_H_

namespace libzkconsent
{

using ppT           = libff::alt_bn128_pp;
using FieldT        = libff::Fr<ppT>;
using HashT         = libzeth::HashT<FieldT>;
using HashTreeT     = libzeth::HashTreeT<FieldT>;

const size_t ZKC_TreeDepth      = libzeth::ZETH_MERKLE_TREE_DEPTH;
const size_t ZKC_STUDYID_SIZE   = libzeth::ZETH_V_SIZE;
const size_t ZKC_CHOICE_SIZE    = 8;

}

#endif //__ZKC_PARAMS_H_
