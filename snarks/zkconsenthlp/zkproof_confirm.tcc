// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZKPROOF_CONFIRM_TCC_
#define __ZKPROOF_CONFIRM_TCC_

namespace libzkconsent
{

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
zkconfirm_gadget<FieldT,HashT,HashTreeT,TreeDepth>::zkconfirm_gadget(
        libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix)
        : libsnark::gadget<FieldT>(pb, annotation_prefix)
{
    // PUBLIC DATA: allocated first so that the protoboard has access.
    cm_consent.allocate(pb, FMT(this->annotation_prefix, " cm_consent"));

    // PRIVATE DATA:
    ZERO.allocate(pb, FMT(this->annotation_prefix, " ZERO"));
    a_pk.reset(new libsnark::digest_variable<FieldT>(pb,libzeth::ZETH_A_PK_SIZE,FMT(this->annotation_prefix, " a_pk")));

    studyid.allocate(pb, ZKC_STUDYID_SIZE, FMT(this->annotation_prefix, " studyid"));
    study_not_zero.allocate(pb, FMT(this->annotation_prefix, " study_not_zero"));
    study_zero_gag.reset(new libsnark::disjunction_gadget<FieldT>(
                        pb, studyid, study_not_zero, FMT(this->annotation_prefix, " study_zero_gag")));

    choice.allocate(pb, FMT(this->annotation_prefix, " choice"));

    // Gadget computing the commitment
    noteConsentOut_gag.reset(new noteconsent_out_gadget<FieldT, HashT>(
                pb, a_pk, studyid, choice, cm_consent));
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
void zkconfirm_gadget<FieldT,HashT,HashTreeT,TreeDepth>::generate_r1cs_constraints()
{
    libsnark::generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), FMT(this->annotation_prefix, " ZERO"));
    libsnark::generate_boolean_r1cs_constraint<FieldT>(this->pb, choice, FMT(this->annotation_prefix, " choice"));

    for (size_t i = 0; i < studyid.size(); i++)
        libsnark::generate_boolean_r1cs_constraint<FieldT>(this->pb, studyid[i], FMT(this->annotation_prefix, " studyid[%zu]", i));

    study_zero_gag->generate_r1cs_constraints();
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(1, study_not_zero, 1),FMT(this->annotation_prefix, " study_not_zero"));

    a_pk->generate_r1cs_constraints();
    noteConsentOut_gag->generate_r1cs_constraints();
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
void zkconfirm_gadget<FieldT,HashT,HashTreeT,TreeDepth>::generate_r1cs_witness(
    const libzeth::bits256      &apk_in,
    const libzeth::bits64       &study_in,
    const libzeth::bits256      &rho_in,
    const libzeth::bits256      &trapr_in,
    bool                        choice_in)
{
    //All boolean inputs are verified for "booleaness" as follows: 
    //  apk_in              in zkconfirm_gadget::generate_r1cs_constraints()
    // 
    //  study_in            in zkconfirm_gadget::generate_r1cs_constraints()
    // 
    //  rho_in              in noteconsent_out_gadget::generate_r1cs_constraints()
    // 
    //  trapr_in            in noteconsent_out_gadget::generate_r1cs_constraints()
    // 
    //  choice_in           in zkconfirm_gadget::generate_r1cs_constraints()

    this->pb.val(ZERO) = FieldT::zero();
    a_pk->generate_r1cs_witness(apk_in.to_vector());

    study_in.fill_variable_array(this->pb, studyid);
    study_zero_gag->generate_r1cs_witness();

    //Choice Output
    this->pb.val(choice) = choice_in ? FieldT::one() : FieldT::zero();
    noteConsentOut_gag->generate_r1cs_witness(rho_in, trapr_in);
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
void zkconfirm_gadget<FieldT,HashT,HashTreeT,TreeDepth>::generate_r1cs_witness_test(
    const std::string&  s_apk,
    const std::string&  s_studyid,
    const std::string&  s_rho,
    const std::string&  s_trapr,
    bool                choice)
{
    libzeth::bits256 a_pk_bits256       = libzeth::bits256::from_hex(s_apk);
    libzeth::bits64  studyid_bits64     = libzeth::bits64::from_hex(s_studyid);
    libzeth::bits256 rho_bits256        = libzeth::bits256::from_hex(s_rho);
    libzeth::bits256 trapr_bits256      = libzeth::bits256::from_hex(s_trapr);

    generate_r1cs_witness(a_pk_bits256, studyid_bits64, rho_bits256, trapr_bits256, choice);
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
bool zkconfirm_gadget<FieldT,HashT,HashTreeT,TreeDepth>::test(
        const std::string&  s_apk,
        const std::string&  s_studyid,
        const std::string&  s_rho,
        const std::string&  s_trapr,
        bool                choice)
{
    libsnark::protoboard<FieldT> pb;
    zkconfirm_gadget<FieldT,HashT,HashTreeT,TreeDepth> confirm_gag(pb);

    confirm_gag.generate_r1cs_constraints();
    confirm_gag.generate_r1cs_witness_test(s_apk, s_studyid, s_rho, s_trapr, choice);

    return pb.is_satisfied();    
}

}


#endif //__ZKPROOF_CONFIRM_TCC_
