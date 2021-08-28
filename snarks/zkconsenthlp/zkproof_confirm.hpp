#ifndef __ZKPROOF_CONFIRM_HPP_
#define __ZKPROOF_CONFIRM_HPP_

namespace libzkconsent
{

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
class zkconfirm_gadget : libsnark::gadget<FieldT>
{
private:
    libsnark::pb_variable<FieldT>                           ZERO;
    std::shared_ptr<libsnark::digest_variable<FieldT>>      a_pk;
    libsnark::pb_variable_array<FieldT>                     studyid;
    libsnark::pb_variable<FieldT>                           choice;
    libsnark::pb_variable<FieldT>                           cm_consent;
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
