// SPDX-License-Identifier: LGPL-3.0+

#ifndef __EXTRA_STUDY_GADGETS_TCC_
#define __EXTRA_STUDY_GADGETS_TCC_

namespace libzkconsent
{

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
study_valid_gadget<FieldT, HashT, HashTreeT, TreeDepth>::study_valid_gadget(
        libsnark::protoboard<FieldT>                &pb,
        const libsnark::pb_variable<FieldT>         &expected_root,
        const libsnark::pb_variable_array<FieldT>   &studyid,
    const std::string                               &annotation_prefix)
        : libsnark::gadget<FieldT>(pb, annotation_prefix)
          , mktree_root(expected_root)
{
    study_not_zero.allocate(pb, FMT(this->annotation_prefix, " study_not_zero"));
    study_zero_gag.reset(new libsnark::disjunction_gadget<FieldT>(
                        pb, studyid, study_not_zero, FMT(this->annotation_prefix, " study_zero_gag")));

    // The packaging gadgets inverts the bit order, so we invert the input
    // so that the packed output is the right way round.
    libsnark::pb_variable_array<FieldT> studyid_inv;
    studyid_inv.insert(studyid_inv.end(),studyid.rbegin(),studyid.rend());
    studyidpck.reset(new libsnark::dual_variable_gadget<FieldT>(
                        pb, studyid_inv, FMT(this->annotation_prefix, " studyidpck")));
    
    libsnark::pb_variable_array<FieldT> *pb_auth_path = new libsnark::pb_variable_array<FieldT>();
    pb_auth_path->allocate(pb, TreeDepth, FMT(this->annotation_prefix, " mktree_path"));
    mktree_path.reset(pb_auth_path);
    mktree_address.allocate(pb, TreeDepth, FMT(this->annotation_prefix, " mktree_address"));

    //Note the root computed by this gadget is allocated to a pb_variable within the 
    //merkle_path_compute gadget itself. We access this using mktree_gag->result()
    //to compare it against the expected root, mktree_root. 
    mktree_gag.reset(new libzeth::merkle_path_compute<FieldT, HashTreeT>(
        pb, TreeDepth, mktree_address, studyidpck->packed, *mktree_path,
        FMT(this->annotation_prefix, " mktree_gag")));
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
void study_valid_gadget<FieldT, HashT, HashTreeT, TreeDepth>::generate_r1cs_constraints()
{
    //Also ensures studyid booleaness
    studyidpck->generate_r1cs_constraints(true);

    study_zero_gag->generate_r1cs_constraints();
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(1, study_not_zero, 1),
        FMT(this->annotation_prefix, " study_not_zero"));

    mktree_gag->generate_r1cs_constraints();
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(1, mktree_gag->result(), mktree_root),
        FMT(this->annotation_prefix, " expected_root authenticator"));
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
void study_valid_gadget<FieldT, HashT, HashTreeT, TreeDepth>::generate_r1cs_witness(
    const std::vector<FieldT> &merkle_path,
    const libzeth::bits_addr<TreeDepth> &merkle_address)
{
    study_zero_gag->generate_r1cs_witness();
    studyidpck->generate_r1cs_witness_from_bits();

    merkle_address.fill_variable_array(this->pb, mktree_address);
    mktree_path->fill_with_field_elements(this->pb, merkle_path);
    mktree_gag->generate_r1cs_witness();    
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
bool study_valid_gadget<FieldT, HashT, HashTreeT, TreeDepth>::test(
    const std::string&  s_ask, 
    const std::string&  s_studyid,
    size_t              mkAddr)
{
    //Construct the circuit
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> merkle_root;
    libsnark::pb_variable_array<FieldT> studyid;

    merkle_root.allocate(pb, " root");
    studyid.allocate(pb, ZKC_STUDYID_SIZE, " studyid");

    study_valid_gadget<FieldT, HashT, HashTreeT, TreeDepth> input_study_g(
        pb, merkle_root, studyid);

    input_study_g.generate_r1cs_constraints();
    //=======================================================

    libzeth::bits64  studyid_bits64 = libzeth::bits64::from_hex(s_studyid);
    FieldT           study_leaf     = libzeth::base_field_element_from_hex<FieldT>(Hex64to256(s_studyid));

    //Compute Merkle Tree values
    libzeth::merkle_tree_field<FieldT, HashTreeT> test_merkle_tree(TreeDepth);
    libzeth::bits_addr<TreeDepth> address_bits = libzeth::bits_addr<TreeDepth>::from_size_t(mkAddr);

    test_merkle_tree.set_value(mkAddr, study_leaf);
    FieldT              root_value  = test_merkle_tree.get_root();
    std::vector<FieldT> path        = test_merkle_tree.get_path(mkAddr);

    //Compute witness
    pb.val(merkle_root) = root_value;
    studyid_bits64.fill_variable_array(pb, studyid);
    input_study_g.generate_r1cs_witness(path, address_bits);

    return pb.is_satisfied();
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
study_in_gadget<FieldT, HashT, HashTreeT, TreeDepth>::study_in_gadget(
        libsnark::protoboard<FieldT>                &pb,
        const libsnark::pb_variable<FieldT>         &ZERO,
        const libsnark::pb_variable<FieldT>         &expected_root,
        const libsnark::pb_variable_array<FieldT>   &studyid,
        std::shared_ptr<libsnark::digest_variable<FieldT>> a_sk,
        std::shared_ptr<libsnark::digest_variable<FieldT>> nullifier,
        const std::string                           &annotation_prefix)
        : libsnark::gadget<FieldT>(pb, annotation_prefix)
{
    studyval_gag.reset(new study_valid_gadget<FieldT, HashT, HashTreeT, TreeDepth>(
        pb, expected_root, studyid,
        FMT(this->annotation_prefix, " studyval_gag")));

    //Nullifier gadget expects a 256-bit study id value.
    //So we consturct the necessary value before passing it to nf_gag
    assert(HashT::get_digest_len() > studyid.size());
    libsnark::pb_variable_array<FieldT> studyid256;
    studyid256.insert(studyid256.end(), HashT::get_digest_len()-studyid.size(), ZERO);
    studyid256.insert(studyid256.end(), studyid.begin(), studyid.end());    

    nf_gag.reset(new PRF_nf_sid_gadget<FieldT, HashT>(pb, ZERO, a_sk->bits, studyid256, nullifier));
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
void study_in_gadget<FieldT, HashT, HashTreeT, TreeDepth>::generate_r1cs_constraints()
{
    studyval_gag->generate_r1cs_constraints();
    nf_gag->generate_r1cs_constraints();
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
void study_in_gadget<FieldT, HashT, HashTreeT, TreeDepth>::generate_r1cs_witness(
    const std::vector<FieldT> &merkle_path,
    const libzeth::bits_addr<TreeDepth> &merkle_address)
{
    studyval_gag->generate_r1cs_witness(merkle_path, merkle_address);    
    nf_gag->generate_r1cs_witness();
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
std::string study_in_gadget<FieldT, HashT, HashTreeT, TreeDepth>::test(
    const std::string&  s_ask, 
    const std::string&  s_studyid,
    size_t              mkAddr)
{
    //Construct the circuit
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    libsnark::pb_variable<FieldT> merkle_root;
    libsnark::pb_variable_array<FieldT> studyid;

    ZERO.allocate(pb, " zero");
    merkle_root.allocate(pb, " root");
    studyid.allocate(pb, ZKC_STUDYID_SIZE, " studyid");

    std::shared_ptr<libsnark::digest_variable<FieldT>> a_sk_digest(
        new libsnark::digest_variable<FieldT>(pb, HashT::get_digest_len(), "a_sk_digest"));
    std::shared_ptr<libsnark::digest_variable<FieldT>> nullifier_digest(
        new libsnark::digest_variable<FieldT>(pb, HashT::get_digest_len(), "nullifier_digest"));
    study_in_gadget<FieldT, HashT, HashTreeT, TreeDepth> input_study_g(
        pb, ZERO, merkle_root, studyid, a_sk_digest, nullifier_digest);

    a_sk_digest->generate_r1cs_constraints();
    input_study_g.generate_r1cs_constraints();
    nullifier_digest->generate_r1cs_constraints();
    //=======================================================

    libzeth::bits256 a_sk_bits256   = libzeth::bits256::from_hex(s_ask);
    libzeth::bits64  studyid_bits64 = libzeth::bits64::from_hex(s_studyid);
    FieldT           study_leaf     = libzeth::base_field_element_from_hex<FieldT>(Hex64to256(s_studyid));

    //...and the Merkle Tree values
    libzeth::merkle_tree_field<FieldT, HashTreeT> test_merkle_tree(TreeDepth);
    libzeth::bits_addr<TreeDepth> address_bits = libzeth::bits_addr<TreeDepth>::from_size_t(mkAddr);

    test_merkle_tree.set_value(mkAddr, study_leaf);
    FieldT root_value = test_merkle_tree.get_root();
    std::vector<FieldT> path  = test_merkle_tree.get_path(mkAddr);

    //Compute witness
    pb.val(ZERO) = FieldT::zero();
    pb.val(merkle_root) = root_value;
    studyid_bits64.fill_variable_array(pb, studyid);
    a_sk_digest->generate_r1cs_witness(libff::bit_vector(a_sk_bits256.to_vector()));
    input_study_g.generate_r1cs_witness(path, address_bits);

    // std::cout << pb.primary_input() << std::endl;
    // std::cout << pb.auxiliary_input() << std::endl;

    if (!pb.is_satisfied())
        return nullptr;

    return digest2hex(nullifier_digest->get_digest());
}

}

#endif //__EXTRA_STUDY_GADGETS_TCC_