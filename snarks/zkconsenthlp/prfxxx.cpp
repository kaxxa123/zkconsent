#include <stdlib.h>
#include <iostream>

#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/circuits/prfs/prf.hpp"
#include "libzeth/core/utils.hpp"
#include "libzeth/zeth_constants.hpp"

#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"

#include "prf_extra_gadgets.hpp"

using pp = libsnark::default_r1cs_ppzksnark_pp;
using FieldT = libff::Fr<pp>;
using HashT = libzeth::BLAKE2s_256<FieldT>;

void   InitSnarks()
{
    pp::init_public_params();
}

//Test Values
//ask = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"
//apk = "2390c9e5370be7355f220b29caf3912ef970d828b73976ae9bfeb1402ce4c1f9"
std::string     PRFapk(const std::string& ask)
{
    return libzkconsent::PRF_1input_nfT<FieldT, HashT, libzeth::PRF_addr_a_pk_gadget<FieldT, HashT>>(
        ask);
}

//Test Values
//ask = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"
//rho = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"
//nf  = "ea43866d185e1bdb84713b699a2966d929d1392488c010c603e46a4cb92986f8"
std::string     PRFConsentnf(const std::string& ask, const std::string& rho)
{
    return libzkconsent::PRF_2input_nfT<FieldT, HashT, libzeth::PRF_nf_gadget<FieldT, HashT>>(
        ask, rho);
}

std::string     PRFIDnf(const std::string& ask, const std::string& rho)
{
    return libzkconsent::PRF_2input_nfT<FieldT, HashT, libzkconsent::PRF_nf_uid_gadget<FieldT, HashT>>(
        ask, rho);
}

std::string     PRFStudynf(const std::string& ask, const std::string& sid)
{
    return libzkconsent::PRF_2input_nfT<FieldT, HashT, libzkconsent::PRF_nf_sid_gadget<FieldT, HashT>>(
        ask, sid);
}