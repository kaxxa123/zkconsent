#include <stdlib.h>
#include <iostream>

#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/circuits/prfs/prf.hpp"
#include "libzeth/core/utils.hpp"
#include "libzeth/zeth_constants.hpp"

#include "prf_extra_gadgets.hpp"
#include "zkc_params.hpp"

void   InitSnarks()
{
    pp::init_public_params();
}

//Test Values
//ask = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"
//apk = "2390c9e5370be7355f220b29caf3912ef970d828b73976ae9bfeb1402ce4c1f9"
std::string     PRFapk(const std::string& ask)
{
    return libzkconsent::PRF_1input<FieldT, HashT, libzeth::PRF_addr_a_pk_gadget<FieldT, HashT>>(
        ask);
}

//Test Values
//ask = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"
//rho = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"
//nf  = "ea43866d185e1bdb84713b699a2966d929d1392488c010c603e46a4cb92986f8"
std::string     PRFConsentnf(const std::string& ask, const std::string& rho)
{
    return libzkconsent::PRF_2input<FieldT, HashT, libzeth::PRF_nf_gadget<FieldT, HashT>>(
        ask, rho);
}

std::string     PRFIDnf(const std::string& ask, const std::string& rho)
{
    return libzkconsent::PRF_2input<FieldT, HashT, libzkconsent::PRF_nf_uid_gadget<FieldT, HashT>>(
        ask, rho);
}

std::string     PRFStudynf(const std::string& ask, const std::string& sid)
{
    return libzkconsent::PRF_2input<FieldT, HashT, libzkconsent::PRF_nf_sid_gadget<FieldT, HashT>>(
        ask, sid);
}

std::string     PRFHtag     (const std::string& ask, const std::string& hsig, size_t index)
{
    return libzkconsent::PRF_3input<FieldT, HashT, libzeth::PRF_pk_gadget<FieldT, HashT>>(
        ask, hsig, index);
}