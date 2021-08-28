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
#include "zkc_interface.hpp"

namespace libzkconsent
{

void            InitSnarks()
{
    ppT::init_public_params();
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
        ask, Hex64to256(sid));
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

std::string      Test_NoteConsent_Input(
                    const std::string&  s_ask, 
                    const std::string&  s_rho,
                    const std::string&  s_trap_r,
                    const std::string&  s_studyid,
                    bool                choice,
                    size_t              mkAddr)
{
    return noteconsent_in_gadget<FieldT, HashT, HashTreeT, ZKC_TreeDepth>::test(
                s_ask, s_rho, s_trap_r, s_studyid, choice, mkAddr);    
}

std::string      Test_NoteConsent_Output(
                    const std::string&  s_apk, 
                    const std::string&  s_rho,
                    const std::string&  s_trap_r,
                    const std::string&  s_studyid,
                    bool                choice)
{
    return noteconsent_out_gadget<FieldT, HashT>::test(
                s_apk, s_rho, s_trap_r, s_studyid, choice);    
}

std::string      Test_Study_Input(
                    const std::string&  s_ask, 
                    const std::string&  s_studyid,
                    size_t              mkAddr)
{
    return study_in_gadget<FieldT, HashT, HashTreeT, ZKC_TreeDepth>::test(
                s_ask, s_studyid, mkAddr);    
}

bool            Test_UserTerminate(
                    const std::string&  s_ask,
                    size_t              mkAddr, 
                    const std::string&  s_rho,
                    const std::string&  s_hsig)
{
    // return zkterminate_gadget<FieldT,HashT,HashTreeT,ZKC_TreeDepth>::test(
    //             s_ask, mkAddr, s_rho, s_hsig);
    return zkterminate_wrap<ppT, FieldT, HashT, HashTreeT, SnarkT, ZKC_TreeDepth>::test(
                    s_ask, mkAddr, s_rho, s_hsig);
}

bool            Test_ConsentMint(
                    const std::string&  s_ask,
                    size_t              mkaddrStudy, 
                    const std::string&  s_studyid,
                    size_t              mkaddrId, 
                    const std::string&  s_rhoId_in,
                    const std::string&  s_rhoId_out,
                    const std::string&  s_rhoConsent_out,
                    const std::string&  s_traprConsent_out,
                    bool                choice_out,
                    const std::string&  s_hsig)
{
    // return zkmint_gadget<FieldT,HashT,HashTreeT,ZKC_TreeDepth>::test(
    //                 s_ask,
    //                 mkaddrStudy, s_studyid, 
    //                 mkaddrId,  s_rhoId_in,
    //                 s_rhoId_out,
    //                 s_rhoConsent_out, s_traprConsent_out, choice_out,
    //                 s_hsig);        

    return zkmint_wrap<ppT, FieldT, HashT, HashTreeT, SnarkT, ZKC_TreeDepth>::test(
                    s_ask,
                    mkaddrStudy, s_studyid, 
                    mkaddrId,  s_rhoId_in,
                    s_rhoId_out,
                    s_rhoConsent_out, s_traprConsent_out, choice_out,
                    s_hsig);
}

bool            Test_ConsentChg(
                    const std::string&  s_ask,
                    size_t              mkaddrStudy, 
                    const std::string&  s_studyid,
                    size_t              mkaddrId, 
                    const std::string&  s_rhoId_in,
                    const std::string&  s_rhoId_out,
                    size_t              mkaddrConsent, 
                    const std::string&  s_rhoConsent_in,
                    const std::string&  s_traprConsent_in,
                    bool                choice_in,
                    const std::string&  s_rhoConsent_out,
                    const std::string&  s_traprConsent_out,
                    const std::string&  s_hsig)
{
    // return zkconsent_gadget<FieldT,HashT,HashTreeT,ZKC_TreeDepth>::test(
    //                 s_ask,
    //                 mkaddrStudy, s_studyid, 
    //                 mkaddrId,  s_rhoId_in,
    //                 s_rhoId_out,
    //                 mkaddrConsent, s_rhoConsent_in, s_traprConsent_in, choice_in,
    //                 s_rhoConsent_out, s_traprConsent_out,
    //                 s_hsig);

    return zkconsent_wrap<ppT, FieldT, HashT, HashTreeT, SnarkT, ZKC_TreeDepth>::test(
                    s_ask,
                    mkaddrStudy, s_studyid, 
                    mkaddrId,  s_rhoId_in,
                    s_rhoId_out,
                    mkaddrConsent, s_rhoConsent_in, s_traprConsent_in, choice_in,
                    s_rhoConsent_out, s_traprConsent_out,
                    s_hsig);
}

bool            Test_ConsentConfirm(
                    const std::string&  s_apk,
                    const std::string&  s_studyid,
                    const std::string&  s_rho,
                    const std::string&  s_trapr,
                    bool                choice)
{
    return zkconfirm_gadget<FieldT,HashT,HashTreeT,ZKC_TreeDepth>::test(
                    s_apk, s_studyid, s_rho, s_trapr, choice);
}

}
