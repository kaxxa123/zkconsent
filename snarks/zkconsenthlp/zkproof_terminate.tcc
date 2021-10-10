// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZKPROOF_TERMINATE_TCC_
#define __ZKPROOF_TERMINATE_TCC_

namespace libzkconsent
{

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
zkterminate_gadget<FieldT,HashT,HashTreeT,TreeDepth>::zkterminate_gadget(
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
    // - [<start> + 1]    cm Id
    // - [<start> + 2]    Nullifier Id
    // - [<start> + 3]    hsig
    // - [<start> + 4]    htag
    // - [<start> + 5]    Residual field element(S)

    mkroot_id.reset(new libsnark::pb_variable<FieldT>);
    mkroot_id->allocate(pb, FMT(this->annotation_prefix, " mkroot_id"));
    cm_id.allocate(pb, FMT(this->annotation_prefix, " cm_id"));
    
    //AlexZ: packed_inputs[4][1]   ========================================
    packed_inputs[0].allocate(pb, 1, FMT(this->annotation_prefix, " in_nf"));
    packed_inputs[1].allocate(pb, 1, FMT(this->annotation_prefix, " hsig"));
    packed_inputs[2].allocate(pb, 1, FMT(this->annotation_prefix, " htag"));
    packed_inputs[3].allocate(pb, 1, FMT(this->annotation_prefix, " residual_bits"));
    // ====================================================================

    // PRIVATE DATA:
    ZERO.allocate(pb, FMT(this->annotation_prefix, " ZERO"));

    nf_id.reset(new libsnark::digest_variable<FieldT>( pb, HashT::get_digest_len(), FMT(this->annotation_prefix, " nf_id")));
    hsig.reset(new libsnark::digest_variable<FieldT>(pb, libzeth::ZETH_HSIG_SIZE, FMT(this->annotation_prefix, " hsig")));
    htag.reset(new libsnark::digest_variable<FieldT>(pb,HashT::get_digest_len(),FMT(this->annotation_prefix, " htag")));
    a_sk.reset(new libsnark::digest_variable<FieldT>(pb,libzeth::ZETH_A_SK_SIZE,FMT(this->annotation_prefix, " a_sk")));
    a_pk.reset(new libsnark::digest_variable<FieldT>(pb,libzeth::ZETH_A_PK_SIZE,FMT(this->annotation_prefix, " a_pk")));

    // We already allocated varaibles on the protoboard for the various unpacked digests
    // We now want unpacked_inputs to bring together the allocation indexes of these variables

    // Now we want unpacked_inputs to reference 
    // the individual bits as follows:
    //  unpacked_inputs[    <htag>] = htag_253-bits
    //  unpacked_inputs[   <nf_id>] = nf_id_253-bits
    //  unpacked_inputs[    <hsig>] = hsig_253-bits
    //  unpacked_inputs[<residual>] = hsig_003-bits || nf_003-bits || htag_003-bits
    digest_variable_assign_to_field_element_and_residual(*htag,   unpacked_inputs[2], unpacked_inputs[PCK_INPUTS-1]);
    digest_variable_assign_to_field_element_and_residual(*nf_id,  unpacked_inputs[0], unpacked_inputs[PCK_INPUTS-1]);
    digest_variable_assign_to_field_element_and_residual(*hsig,   unpacked_inputs[1], unpacked_inputs[PCK_INPUTS-1]);

    //The multipacking_gadget(s) packs our unpacked_inputs (bits) to our packed_inputs (field elements)
    packers[0].reset(new libsnark::multipacking_gadget<FieldT>(
                pb,unpacked_inputs[0],packed_inputs[0],FieldT::capacity(),FMT(this->annotation_prefix, " packer_nullifier")));

    packers[1].reset(new libsnark::multipacking_gadget<FieldT>(
                pb,unpacked_inputs[1],packed_inputs[1],FieldT::capacity(),FMT(this->annotation_prefix, " packer_hsig")));

    packers[2].reset(new libsnark::multipacking_gadget<FieldT>(
                pb,unpacked_inputs[2],packed_inputs[2],FieldT::capacity(),FMT(this->annotation_prefix, " packer_htag")));

    packers[3].reset(new libsnark::multipacking_gadget<FieldT>(
                pb,unpacked_inputs[3], packed_inputs[3], FieldT::capacity(),FMT(this->annotation_prefix, " packer_residual_bits")));

    a_pk_gag.reset(new libzeth::PRF_addr_a_pk_gadget<FieldT, HashT>(
                pb, ZERO, a_sk->bits, a_pk));
    noteIdIn_gag.reset(new noteid_in_gadget<FieldT, HashT, HashTreeT, TreeDepth>(
                pb, ZERO, *mkroot_id, a_sk, a_pk, nf_id));
    noteIdOut_gag.reset(new noteid_out_gadget<FieldT, HashT>(
                pb, a_pk, cm_id));
    htag_gadget.reset(new libzeth::PRF_pk_gadget<FieldT, HashT>(
                pb, ZERO, a_sk->bits, hsig->bits, 0, htag));
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
void zkterminate_gadget<FieldT,HashT,HashTreeT,TreeDepth>::generate_r1cs_constraints()
{
    libsnark::generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), FMT(this->annotation_prefix, " ZERO"));

    // The `true` passed to `generate_r1cs_constraints` ensures that all
    // inputs are boolean strings
    for (size_t i = 0; i < packers.size(); i++)
        packers[i]->generate_r1cs_constraints(true);

    a_sk->generate_r1cs_constraints();
    a_pk_gag->generate_r1cs_constraints();
    noteIdIn_gag->generate_r1cs_constraints();
    noteIdOut_gag->generate_r1cs_constraints();
    htag_gadget->generate_r1cs_constraints();
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
void zkterminate_gadget<FieldT,HashT,HashTreeT,TreeDepth>::generate_r1cs_witness(
        const libzeth::bits256      &ask_in,
        const FieldT                &mkrootId,
        const std::vector<FieldT>   &mkpathId,
        const libzeth::bits_addr<TreeDepth> &mkaddrId,
        const libzeth::bits256      &rhoId_in,
        const libzeth::bits256      &rhoId_out,
        const libzeth::bits256      &hsig_in)
{
    //All boolean inputs are verified for "booleaness" as follows: 
    //  ask_in      in zkterminate_gadget::generate_r1cs_constraints()
    //
    //  mkaddrId    in noteid_in_gadget -> 
    //              merkle_path_compute ->  
    //              merkle_path_selector::generate_r1cs_constraints()
    //                  libsnark::r1cs_constraint<FieldT>(is_right, 1 - is_right, 0)
    //
    //  rhoId_in    in noteid_in_gadget::generate_r1cs_constraints()
    //
    //  rhoId_out   in noteid_out_gadget::generate_r1cs_constraints()
    //
    //  hsig_in     in zkterminate_gadget::generate_r1cs_constraints()
    //                  packers[<hsig>>]->generate_r1cs_constraints(true);

    this->pb.val(ZERO) = FieldT::zero();
    a_sk->generate_r1cs_witness(ask_in.to_vector());
    a_pk_gag->generate_r1cs_witness();

    //Id Input
    this->pb.val(*mkroot_id) = mkrootId;
    noteIdIn_gag->generate_r1cs_witness(mkpathId, mkaddrId, rhoId_in);

    //Id Output
    noteIdOut_gag->generate_r1cs_witness(rhoId_out);

    //Malleability
    hsig->generate_r1cs_witness(hsig_in.to_vector());
    htag_gadget->generate_r1cs_witness();

    for (size_t i = 0; i < packers.size(); i++) {
        packers[i]->generate_r1cs_witness_from_bits();
    }
}


template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
void zkterminate_gadget<FieldT,HashT,HashTreeT,TreeDepth>::generate_r1cs_witness_test(
        const std::string&  s_ask,
        size_t              mkaddrId, 
        const std::string&  s_rhoId_in,
        const std::string&  s_rhoId_out,
        const std::string&  s_hsig)
{
    //Compute the cm (mk leaf) from the given ask and rho
    std::string s_apk = PRF_1input<FieldT, HashT, libzeth::PRF_addr_a_pk_gadget<FieldT, HashT>>(s_ask);

    //Id Input
    std::string s_cmId  = comm_id_gadget<FieldT, HashT>::get_cm(s_apk, s_rhoId_in);
    FieldT cmId         = FieldT(s_cmId.c_str());

    //...and the Merkle Tree values 
    libzeth::merkle_tree_field<FieldT, HashTreeT> test_mktreeId(TreeDepth);
    libzeth::bits_addr<TreeDepth> mkaddress_Id = libzeth::bits_addr<TreeDepth>::from_size_t(mkaddrId);

    test_mktreeId.set_value(mkaddrId, cmId);
    FieldT merkle_root_Id = test_mktreeId.get_root();
    std::vector<FieldT> mkpath_Id  = test_mktreeId.get_path(mkaddrId);

    //We now have all the necessary values to run zkterminate_gadget
    libzeth::bits256 a_sk_bits256       = libzeth::bits256::from_hex(s_ask);
    libzeth::bits256 rhoId_In_bits256   = libzeth::bits256::from_hex(s_rhoId_in);
    libzeth::bits256 rhoId_Out_bits256  = libzeth::bits256::from_hex(s_rhoId_out);
    libzeth::bits256 hsig_bits256       = libzeth::bits256::from_hex(s_hsig);

    generate_r1cs_witness(
            a_sk_bits256, 
            merkle_root_Id,     std::move(mkpath_Id),       mkaddress_Id,       rhoId_In_bits256,
            rhoId_Out_bits256, 
            hsig_bits256);
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
bool zkterminate_gadget<FieldT,HashT,HashTreeT,TreeDepth>::test(
        const std::string&  s_ask,
        size_t              mkaddrId, 
        const std::string&  s_rhoId_in,
        const std::string&  s_rhoId_out,
        const std::string&  s_hsig)
{
    libsnark::protoboard<FieldT> pb;
    zkterminate_gadget<FieldT, HashT, HashTreeT, TreeDepth> term_gag(pb);

    term_gag.generate_r1cs_constraints();
    term_gag.generate_r1cs_witness_test(
                        s_ask,
                        mkaddrId, s_rhoId_in, s_rhoId_out,
                        s_hsig);

    return pb.is_satisfied();    
}

}

#endif //__ZKPROOF_TERMINATE_TCC_
