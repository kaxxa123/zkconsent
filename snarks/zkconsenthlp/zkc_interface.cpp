#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <vector>

#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/circuits/prfs/prf.hpp"
#include "libzeth/core/utils.hpp"
#include "libzeth/zeth_constants.hpp"

#include "zkc_params.hpp"
#include "zkc_helpers.hpp"
#include "extra_prf_gadgets.hpp"
#include "extra_cm_gadgets.hpp"
#include "extra_note_types.hpp"
#include "extra_note_gadgets.hpp"
#include "zkc_interface.hpp"

namespace libzkconsent
{

void            InitSnarks()
{
    pp::init_public_params();
}

std::string     FieldBound(const std::string& value)
{
    FieldT fval = FieldT(value.c_str());
    return FieldtoString(fval);
}

//Test Values
//ask = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"
//apk = "2390c9e5370be7355f220b29caf3912ef970d828b73976ae9bfeb1402ce4c1f9"
std::string     PRFapk(const std::string& ask)
{
    return PRF_1input<FieldT, HashT, libzeth::PRF_addr_a_pk_gadget<FieldT, HashT>>(
        ask);
}

//Test Values
//ask = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"
//rho = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"
//nf  = "ea43866d185e1bdb84713b699a2966d929d1392488c010c603e46a4cb92986f8"
std::string     PRFConsentnf(const std::string& ask, const std::string& rho)
{
    return PRF_2input<FieldT, HashT, libzeth::PRF_nf_gadget<FieldT, HashT>>(
        ask, rho);
}

std::string     PRFIDnf(const std::string& ask, const std::string& rho)
{
    return PRF_2input<FieldT, HashT, PRF_nf_uid_gadget<FieldT, HashT>>(
        ask, rho);
}

std::string     PRFStudynf(const std::string& ask, const std::string& sid)
{
    return PRF_2input<FieldT, HashT, PRF_nf_sid_gadget<FieldT, HashT>>(
        ask, sid);
}

std::string     PRFHtag     (const std::string& ask, const std::string& hsig, size_t index)
{
    return PRF_3input<FieldT, HashT, libzeth::PRF_pk_gadget<FieldT, HashT>>(
        ask, hsig, index);
}

std::string     CMMid(const std::string& a_pk, const std::string& rho)
{
    return comm_id_gadget<FieldT, HashT>::get_cm(a_pk, rho);    
}

std::string     CMMconsent(
                    const std::string& sapk, 
                    const std::string& srho,
                    const std::string& strap_r,
                    const std::string& sid,
                    bool bChoice)
{
    return comm_consent_gadget<FieldT, HashT>::get_cm(sapk, srho, strap_r, sid, bChoice);    
}

std::string      Test_NoteId_Input(
                    const std::string&  s_ask, 
                    const std::string&  s_rho,
                    size_t              mkAddr)
{
    return noteid_in_gadget<FieldT, HashT, HashTreeT, ZKC_TreeDepth>::test(
                s_ask, s_rho, mkAddr);
}

std::string      Test_NoteId_Output(
                    const std::string&  s_apk, 
                    const std::string&  s_rho)
{
    return noteid_out_gadget<FieldT, HashT>::test(
                s_apk, s_rho);
}


}
