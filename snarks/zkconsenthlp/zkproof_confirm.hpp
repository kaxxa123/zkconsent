// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZKPROOF_CONFIRM_HPP_
#define __ZKPROOF_CONFIRM_HPP_

namespace libzkconsent
{

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
class zkconfirm_gadget : libsnark::gadget<FieldT>
{
private:
    //Public
    libsnark::pb_variable<FieldT>                           cm_consent;

    //Private
    libsnark::pb_variable<FieldT>                           ZERO;
    std::shared_ptr<libsnark::digest_variable<FieldT>>      a_pk;

    //We also require extra validation to ensure studyid != 0
    libsnark::pb_variable_array<FieldT>                     studyid;
    libsnark::pb_variable<FieldT>                           study_not_zero;
    std::shared_ptr<libsnark::disjunction_gadget<FieldT>>   study_zero_gag;

    libsnark::pb_variable<FieldT>                           choice;
    std::shared_ptr<noteconsent_out_gadget<FieldT, HashT>>  noteConsentOut_gag;

public:
    explicit zkconfirm_gadget(
        libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix = " zkconfirm_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness(
        const libzeth::bits256      &apk_in,
        const libzeth::bits64       &study_in,
        const libzeth::bits256      &rho_in,
        const libzeth::bits256      &trapr_in,
        bool                        choice_in);

    void generate_r1cs_witness_test(
        const std::string&  s_apk,
        const std::string&  s_studyid,
        const std::string&  s_rho,
        const std::string&  s_trapr,
        bool                choice);        

    static bool test(
        const std::string&  s_apk,
        const std::string&  s_studyid,
        const std::string&  s_rho,
        const std::string&  s_trapr,
        bool                choice);        

};

}

#include "zkproof_confirm.tcc"

#endif //__ZKPROOF_CONFIRM_HPP_
