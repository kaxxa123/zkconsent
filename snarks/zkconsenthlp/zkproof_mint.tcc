#ifndef __ZKPROOF_MINT_TCC_
#define __ZKPROOF_MINT_TCC_

namespace libzkconsent
{

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
zkmint_gadget<FieldT,HashT,HashTreeT,TreeDepth>::zkmint_gadget(
        libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix)
        : libsnark::gadget<FieldT>(pb, annotation_prefix)
{
    // PUBLIC DATA: allocated first so that the protoboard has access.
    //
    // Allocation is currently performed here in the following order
    // (with the protoboard owner determining whether these are primary
    // or auxiliary inputs to the circuit):
    //     PB Index       Field
    // - [<start> + 0]    Root Id
    // - [<start> + 1]    Root Study
    // - [<start> + 2]    cm Id
    // - [<start> + 3]    cm Consent
    // - [<start> + 4]    Nullifier Id
    // - [<start> + 5]    Nullifier Study
    // - [<start> + 6]    hsig
    // - [<start> + 7]    htag
    // - [<start> + 8]    Residual field element(S)

    mkroot_id.reset(new libsnark::pb_variable<FieldT>);
    mkroot_study.reset(new libsnark::pb_variable<FieldT>);

    mkroot_id->allocate(pb, FMT(" mkroot_id"));
    mkroot_study->allocate(pb, FMT(" mkroot_study"));
    cm_id.allocate(pb, FMT(" cm_id"));
    cm_consent.allocate(pb, FMT(" cm_consent"));

    //AlexZ: packed_inputs[6][1]   ========================================
    packed_inputs[0].allocate(pb, 1, FMT(" in_nf_id"));
    packed_inputs[1].allocate(pb, 1, FMT(" in_nf_study"));
    packed_inputs[2].allocate(pb, 1, FMT(" hsig"));
    packed_inputs[3].allocate(pb, 1, FMT(" htag"));
    packed_inputs[4].allocate(pb, 1, FMT(" residual_bits"));
    // ====================================================================

    // PRIVATE DATA:
    // Allocate a ZERO variable
    // TODO: check whether/why this is actually needed
    ZERO.allocate(pb, FMT(this->annotation_prefix, " ZERO"));

    hsig.reset(new libsnark::digest_variable<FieldT>(pb, libzeth::ZETH_HSIG_SIZE, FMT(" hsig")));
    nf_id.reset(new libsnark::digest_variable<FieldT>(pb, HashT::get_digest_len(), FMT(" nf_id")));
    nf_study.reset(new libsnark::digest_variable<FieldT>(pb, HashT::get_digest_len(), FMT(" nf_study")));
    a_sk.reset(new libsnark::digest_variable<FieldT>(pb,libzeth::ZETH_A_SK_SIZE,FMT(" a_sk")));
    htag.reset(new libsnark::digest_variable<FieldT>(pb,HashT::get_digest_len(),FMT(this->annotation_prefix, " htag")));

    studyid.allocate(pb, ZKC_STUDYID_SIZE, FMT(this->annotation_prefix, " studyid"));
    choice.allocate(pb, FMT(this->annotation_prefix, " choice"));

    // We already allocated varaibles on the protoboard for the various unpacked digests
    // We now want unpacked_inputs to bring together the allocation indexes of these variables

    // Now we want unpacked_inputs to reference 
    // the individual bits as follows:
    //  unpacked_inputs[    <htag>] = htag_253-bits
    //  unpacked_inputs[   <nf_id>] = nf_id_253-bits
    //  unpacked_inputs[   <nf_st>] = nf_st_253-bits
    //  unpacked_inputs[    <hsig>] = hsig_253-bits
    //  unpacked_inputs[<residual>] = hsig_003-bits || nf_st_003-bits || nf_id_003-bits || htag_003-bits || StudyId_064-bits || Choice_001bit
    unpacked_inputs[PCK_INPUTS-1].emplace_back(choice);
    assign_public_value_to_residual_bits(studyid, unpacked_inputs[PCK_INPUTS-1]);
    digest_variable_assign_to_field_element_and_residual(*htag,     unpacked_inputs[3], unpacked_inputs[PCK_INPUTS-1]);
    digest_variable_assign_to_field_element_and_residual(*nf_id,    unpacked_inputs[0], unpacked_inputs[PCK_INPUTS-1]);
    digest_variable_assign_to_field_element_and_residual(*nf_study, unpacked_inputs[1], unpacked_inputs[PCK_INPUTS-1]);
    digest_variable_assign_to_field_element_and_residual(*hsig,     unpacked_inputs[2], unpacked_inputs[PCK_INPUTS-1]);

    //The multipacking_gadget(s) packs our unpacked_inputs (bits) to our packed_inputs (field elements)
    packers[0].reset(new libsnark::multipacking_gadget<FieldT>(
                pb,unpacked_inputs[0],packed_inputs[0],FieldT::capacity(),FMT(" packer_nf_id")));

    packers[1].reset(new libsnark::multipacking_gadget<FieldT>(
                pb,unpacked_inputs[1],packed_inputs[1],FieldT::capacity(),FMT(" packer_nf_study")));

    packers[2].reset(new libsnark::multipacking_gadget<FieldT>(
                pb,unpacked_inputs[2],packed_inputs[2],FieldT::capacity(),FMT(" packer_hsig")));

    packers[3].reset(new libsnark::multipacking_gadget<FieldT>(
                pb,unpacked_inputs[3],packed_inputs[3],FieldT::capacity(),FMT(" packer_htag")));

    packers[4].reset(new libsnark::multipacking_gadget<FieldT>(
                pb,unpacked_inputs[4], packed_inputs[4], FieldT::capacity(),FMT(" packer_residual_bits")));


    noteIdIn_gag.reset(new noteid_in_gadget<FieldT, HashT, HashTreeT, TreeDepth>(
                pb, ZERO, *mkroot_id, a_sk, nf_id));
    study_gag.reset(new study_in_gadget<FieldT, HashT, HashTreeT, TreeDepth>(
                pb, ZERO, *mkroot_study, studyid, a_sk, nf_study));
    htag_gag.reset(new libzeth::PRF_pk_gadget<FieldT, HashT>(
                pb, ZERO, a_sk->bits, hsig->bits, 0, htag));

    noteIdOut_gag.reset(new noteid_out_gadget<FieldT, HashT>(
                pb, cm_id));
    noteConsentOut_gag.reset(new noteconsent_out_gadget<FieldT, HashT>(
                pb, cm_consent));
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
void zkmint_gadget<FieldT,HashT,HashTreeT,TreeDepth>::generate_r1cs_constraints()
{
    // The `true` passed to `generate_r1cs_constraints` ensures that all
    // inputs are boolean strings
    for (size_t i = 0; i < packers.size(); i++)
        packers[i]->generate_r1cs_constraints(true);

    a_sk->generate_r1cs_constraints();

    // Constrain `ZERO`: Make sure that the ZERO variable is the zero of the field
    libsnark::generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), FMT(" ZERO"));

    noteIdIn_gag->generate_r1cs_constraints();
    study_gag->generate_r1cs_constraints();
    htag_gag->generate_r1cs_constraints();
    noteIdOut_gag->generate_r1cs_constraints();
    noteConsentOut_gag->generate_r1cs_constraints();

    //Ensure that all gadgets are working with the same study id, and ask
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
void zkmint_gadget<FieldT,HashT,HashTreeT,TreeDepth>::generate_r1cs_witness()
    // const FieldT &rt,
    // const zkc_input_note<FieldT, id_note, TreeDepth> &inputs,
    // const libzeth::bits256 h_sig_in)
{
    
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
bool zkmint_gadget<FieldT,HashT,HashTreeT,TreeDepth>::test()
    // const std::string&  s_ask, 
    // const std::string&  s_rho,
    // const std::string&  s_hsig,
    // size_t              mkAddr)
{
    libsnark::protoboard<FieldT> pb;
    zkmint_gadget<FieldT,HashT,HashTreeT,TreeDepth> proof_gag(pb);

    return true;
}

}


#endif //__ZKPROOF_MINT_TCC_
