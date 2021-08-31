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

#include "zkjson.hpp"

zkterminate_json& zkterminate_json::set(const boost::json::object& objJSON)
{
    extract(objJSON, a_sk, "a_sk");
    extract(objJSON, mkaddrId, "mkaddrId");
    extract(objJSON, rho, "rho");
    extract(objJSON, hsig, "hsig");

    return (*this);
}

void zkterminate_json::trace()
{
    std::cout <<  std::endl;
    std::cout << " ------ zkterminate proof parameters ---------"  << std::endl;
    std::cout << " a_sk:     " << a_sk << std::endl;
    std::cout << " mkaddrId: " << mkaddrId << std::endl;
    std::cout << " rho:      " << rho << std::endl;
    std::cout << " hsig:     " << hsig << std::endl;
    std::cout << " -------------------------------------------"  << std::endl;
    std::cout <<  std::endl;
}

libzeth::extended_proof<ppT, SnarkT>    zkterminate_json::prove_test(circuitT& aZkp, const typename SnarkT::proving_key &proving_key) const
{
    std::vector<FieldT> out_public_data;
    return aZkp.prove_test(a_sk, mkaddrId, rho, hsig, proving_key, out_public_data);
}

//========================================================================================
zkmint_json& zkmint_json::set(const boost::json::object& objJSON)
{
    extract(objJSON, a_sk, "a_sk");
    extract(objJSON, mkaddrStudy, "mkaddrStudy");
    extract(objJSON, studyid, "studyid");
    extract(objJSON, mkaddrId, "mkaddrId");
    extract(objJSON, rhoId_in, "rhoId_in");
    extract(objJSON, rhoId_out, "rhoId_out");
    extract(objJSON, rhoConsent_out, "rhoConsent_out");
    extract(objJSON, traprConsent_out, "traprConsent_out");
    extract(objJSON, choice_out, "choice_out");
    extract(objJSON, hsig, "hsig");

    return (*this);
}

void zkmint_json::trace()
{
    std::cout <<  std::endl;
    std::cout << " ------ zkconfirm proof parameters ---------"  << std::endl;
    std::cout << " a_sk:             " << a_sk << std::endl;
    std::cout << " mkaddrStudy:      " << mkaddrStudy << std::endl;
    std::cout << " studyid:          " << studyid << std::endl;
    std::cout << " mkaddrId:         " << mkaddrId << std::endl;
    std::cout << " rhoId_in:         " << rhoId_in << std::endl;
    std::cout << " rhoId_out:        " << rhoId_out << std::endl;
    std::cout << " rhoConsent_out:   " << rhoConsent_out << std::endl;
    std::cout << " traprConsent_out: " << traprConsent_out << std::endl;
    std::cout << " choice_out:       " << choice_out << std::endl;
    std::cout << " hsig:             " << hsig << std::endl;
    std::cout << " -------------------------------------------"  << std::endl;
    std::cout <<  std::endl;
}

libzeth::extended_proof<ppT, SnarkT>    zkmint_json::prove_test(circuitT& aZkp, const typename SnarkT::proving_key &proving_key) const
{
    std::vector<FieldT> out_public_data;
    return aZkp.prove_test( a_sk, 
                            mkaddrStudy, studyid, 
                            mkaddrId, rhoId_in, rhoId_out, 
                            rhoConsent_out, traprConsent_out, 
                            choice_out, hsig, proving_key, out_public_data);
}

//========================================================================================
zkconsent_json& zkconsent_json::set(const boost::json::object& objJSON)
{
    extract(objJSON, a_sk, "a_sk");
    extract(objJSON, mkaddrStudy, "mkaddrStudy");
    extract(objJSON, studyid, "studyid");
    extract(objJSON, mkaddrId, "mkaddrId");
    extract(objJSON, rhoId_in, "rhoId_in");
    extract(objJSON, rhoId_out, "rhoId_out");
    extract(objJSON, mkaddrConsent, "mkaddrConsent");
    extract(objJSON, rhoConsent_in, "rhoConsent_in");
    extract(objJSON, traprConsent_in, "traprConsent_in");
    extract(objJSON, choice_in, "choice_in");
    extract(objJSON, rhoConsent_out, "rhoConsent_out");
    extract(objJSON, traprConsent_out, "traprConsent_out");
    extract(objJSON, hsig, "hsig");

    return (*this);
}

void zkconsent_json::trace()
{
    std::cout <<  std::endl;
    std::cout << " ------ zkconsent proof parameters ---------"  << std::endl;
    std::cout << " a_sk:             " << a_sk << std::endl;
    std::cout << " mkaddrStudy:      " << mkaddrStudy << std::endl;
    std::cout << " studyid:          " << studyid << std::endl;
    std::cout << " mkaddrId:         " << mkaddrId << std::endl;
    std::cout << " rhoId_in:         " << rhoId_in << std::endl;
    std::cout << " rhoId_out:        " << rhoId_out << std::endl;
    std::cout << " mkaddrConsent:    " << mkaddrConsent << std::endl;
    std::cout << " rhoConsent_in:    " << rhoConsent_in << std::endl;
    std::cout << " traprConsent_in:  " << traprConsent_in << std::endl;
    std::cout << " choice_in:        " << choice_in << std::endl;
    std::cout << " rhoConsent_out:   " << rhoConsent_out << std::endl;
    std::cout << " traprConsent_out: " << traprConsent_out << std::endl;
    std::cout << " hsig:             " << hsig << std::endl;
    std::cout << " -------------------------------------------"  << std::endl;
    std::cout <<  std::endl;
}

libzeth::extended_proof<ppT, SnarkT>    zkconsent_json::prove_test(circuitT& aZkp, const typename SnarkT::proving_key &proving_key) const
{
    std::vector<FieldT> out_public_data;
    return aZkp.prove_test( a_sk, 
                            mkaddrStudy, studyid, 
                            mkaddrId, rhoId_in, rhoId_out, 
                            mkaddrConsent, rhoConsent_in, traprConsent_in, choice_in,
                            rhoConsent_out, traprConsent_out, 
                            hsig, proving_key, out_public_data);
}

//========================================================================================
zkconfirm_json& zkconfirm_json::set(const boost::json::object& objJSON)
{
    extract(objJSON, a_pk, "a_pk");
    extract(objJSON, studyid, "studyid");
    extract(objJSON, rho, "rho");
    extract(objJSON, trapr, "trapr");
    extract(objJSON, choice, "choice");

    return (*this);
}

void zkconfirm_json::trace()
{
    std::cout <<  std::endl;
    std::cout << " ------ zkconfirm proof parameters ---------"  << std::endl;
    std::cout << " a_pk:    " << a_pk << std::endl;
    std::cout << " studyid: " << studyid << std::endl;
    std::cout << " rho:     " << rho << std::endl;
    std::cout << " trapr:   " << trapr << std::endl;
    std::cout << " choice:  " << (choice? "yes" : "no") << std::endl;
    std::cout << " -------------------------------------------"  << std::endl;
    std::cout <<  std::endl;
}

libzeth::extended_proof<ppT, SnarkT>    zkconfirm_json::prove_test(circuitT& aZkp, const typename SnarkT::proving_key &proving_key) const
{
    return aZkp.prove_test(a_pk, studyid, rho, trapr, choice, proving_key);
}
