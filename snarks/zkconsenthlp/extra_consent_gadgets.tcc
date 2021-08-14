#ifndef __EXTRA_CONSENT_GADGETS_TCC_
#define __EXTRA_CONSENT_GADGETS_TCC_

namespace libzkconsent
{

//================================================================================
template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
noteconsent_in_gadget<FieldT, HashT, HashTreeT, TreeDepth>::noteconsent_in_gadget(
        libsnark::protoboard<FieldT>        &pb,
        const libsnark::pb_variable<FieldT> &ZERO,
        const libsnark::pb_variable<FieldT> &expected_root,
        std::shared_ptr<libsnark::digest_variable<FieldT>> a_sk,
        std::shared_ptr<libsnark::digest_variable<FieldT>> nullifier,
        const std::string &annotation_prefix)
        : libsnark::gadget<FieldT>(pb, annotation_prefix), 
          mktree_root(expected_root)
{
    rho.allocate(pb, libzeth::ZETH_RHO_SIZE,   FMT(this->annotation_prefix, " rho"));
    trap_r.allocate(pb, libzeth::ZETH_R_SIZE,  FMT(this->annotation_prefix, " trap_r"));
    studyid.allocate(pb, ZKC_STUDYID_SIZE,     FMT(this->annotation_prefix, " studyid"));
    choice.allocate(pb, FMT(this->annotation_prefix, " choice"));
    a_pk.reset(new libsnark::digest_variable<FieldT>(pb, HashT::get_digest_len(), FMT(this->annotation_prefix, " a_pk")));
    
    cm.allocate(pb, FMT(this->annotation_prefix, " commitment"));

    libsnark::pb_variable_array<FieldT> *pb_auth_path = new libsnark::pb_variable_array<FieldT>();
    pb_auth_path->allocate(pb, TreeDepth, FMT(this->annotation_prefix, " mktree_path"));
    mktree_path.reset(pb_auth_path);
    mktree_address.allocate(pb, TreeDepth, FMT(this->annotation_prefix, " mktree_address"));

    // 1. Given a_sk compute a_pk
    // 2. Given a_sk and rho compute nullifer
    // 3. Given rho, r, studyid, choice and the computed a_pk, compute cm
    // 4. Given the computed cm (leaf), combine it with the mktree address/path 
    //    to compute the root. 
    a_pk_gag.reset(new libzeth::PRF_addr_a_pk_gadget<FieldT, HashT>(pb, ZERO, a_sk->bits, a_pk));
    nf_gag.reset(new libzeth::PRF_nf_gadget<FieldT, HashT>(pb, ZERO, a_sk->bits, rho, nullifier));
    cm_gag.reset(new comm_consent_gadget<FieldT, HashT>(pb, a_pk->bits, rho, trap_r, studyid, choice, cm));

    //Note the root computed by this gadget is allocated to a pb_variable within the 
    //merkle_path_compute gadget itself. We access this using mktree_gag->result()
    //to compare it against the expected root, mktree_root. 
    mktree_gag.reset(new libzeth::merkle_path_compute<FieldT, HashTreeT>(
        pb, TreeDepth, mktree_address, cm, *mktree_path,
        FMT(this->annotation_prefix, " mktree_gag")));
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
void noteconsent_in_gadget<FieldT, HashT, HashTreeT, TreeDepth>::generate_r1cs_constraints()
{
    for (size_t i = 0; i < libzeth::ZETH_RHO_SIZE; i++)
        libsnark::generate_boolean_r1cs_constraint<FieldT>(this->pb, rho[i], FMT(this->annotation_prefix, " rho[%zu]", i));

    for (size_t i = 0; i < libzeth::ZETH_R_SIZE; i++)
        libsnark::generate_boolean_r1cs_constraint<FieldT>(this->pb, trap_r[i], FMT(this->annotation_prefix, " trap_r[%zu]", i));

    for (size_t i = 0; i < ZKC_STUDYID_SIZE; i++)
        libsnark::generate_boolean_r1cs_constraint<FieldT>(this->pb, studyid[i], FMT(this->annotation_prefix, " studyid[%zu]", i));

    libsnark::generate_boolean_r1cs_constraint<FieldT>(this->pb, choice, FMT(this->annotation_prefix, " choice"));

    a_pk_gag->generate_r1cs_constraints();
    nf_gag->generate_r1cs_constraints();
    cm_gag->generate_r1cs_constraints();
    mktree_gag->generate_r1cs_constraints();

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(1, mktree_gag->result(), mktree_root),
        FMT(this->annotation_prefix, " expected_root authenticator"));    
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
void noteconsent_in_gadget<FieldT, HashT, HashTreeT, TreeDepth>::generate_r1cs_witness(
        const std::vector<FieldT> &merkle_path,
        const libzeth::bits_addr<TreeDepth> &merkle_address,
        const consent_note &note)
{
    // a_sk -> a_pk
    a_pk_gag->generate_r1cs_witness();

    // (a_sk, rho) -> nf
    note.rho.fill_variable_array(this->pb, rho);
    nf_gag->generate_r1cs_witness();

    // [(a_sk -> a_pk), rho, r, studyid, choice] -> cm
    note.trap_r.fill_variable_array(this->pb, trap_r);
    note.studyid.fill_variable_array(this->pb, studyid);
    this->pb.val(choice) = note.choice ? FieldT::one() : FieldT::zero();
    cm_gag->generate_r1cs_witness();

    // [([(a_sk -> a_pk), rho, r, studyid, choice] -> cm), mktree_address, mktree_path] -> <root>
    merkle_address.fill_variable_array(this->pb, mktree_address);
    mktree_path->fill_with_field_elements(this->pb, merkle_path);
    mktree_gag->generate_r1cs_witness();
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
std::string noteconsent_in_gadget<FieldT, HashT, HashTreeT, TreeDepth>::test(
        const std::string&  s_ask, 
        const std::string&  s_rho,
        const std::string&  s_trap_r,
        const std::string&  s_studyid,
        bool                choice,
        size_t              mkAddr)
{
    //Construct the circuit
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    libsnark::pb_variable<FieldT> merkle_root;

    ZERO.allocate(pb, "zero");
    std::shared_ptr<libsnark::digest_variable<FieldT>> a_sk_digest(new libsnark::digest_variable<FieldT>(pb, HashT::get_digest_len(), "a_sk_digest"));
    std::shared_ptr<libsnark::digest_variable<FieldT>> nullifier_digest(new libsnark::digest_variable<FieldT>(pb, HashT::get_digest_len(), "nullifier_digest"));
    merkle_root.allocate(pb, "root");
    noteconsent_in_gadget<FieldT, HashT, HashTreeT, TreeDepth> input_note_g(
        pb, ZERO, merkle_root, a_sk_digest, nullifier_digest);

    a_sk_digest->generate_r1cs_constraints();
    input_note_g.generate_r1cs_constraints();
    nullifier_digest->generate_r1cs_constraints();
    //=======================================================

    //Compute the cm from the given ask and rho
    std::string s_apk = PRF_1input<FieldT, HashT, libzeth::PRF_addr_a_pk_gadget<FieldT, HashT>>(s_ask);
    std::string s_cm  = comm_consent_gadget<FieldT, HashT>::get_cm(s_apk, s_rho, s_trap_r, s_studyid, choice);
    FieldT cm_field   = FieldT(s_cm.c_str());

    //...and the Merkle Tree values
    libzeth::merkle_tree_field<FieldT, HashTreeT> test_merkle_tree(TreeDepth);
    libzeth::bits_addr<TreeDepth> address_bits = libzeth::bits_addr<TreeDepth>::from_size_t(mkAddr);

    test_merkle_tree.set_value(mkAddr, cm_field);
    FieldT root_value = test_merkle_tree.get_root();
    std::vector<FieldT> path  = test_merkle_tree.get_path(mkAddr);

    //Compute witness
    libzeth::bits256 a_sk_bits256   = libzeth::bits256::from_hex(s_ask);
    libzeth::bits256 rho_bits256    = libzeth::bits256::from_hex(s_rho);
    libzeth::bits256 trap_r_bits256 = libzeth::bits256::from_hex(s_trap_r);
    libzeth::bits64  studyid_bits64 = libzeth::bits64::from_hex(s_studyid);
    libzeth::bits256 a_pk_bits256   = libzeth::bits256::from_hex(s_apk);

    pb.val(ZERO) = FieldT::zero();
    pb.val(merkle_root) = root_value;
    a_sk_digest->generate_r1cs_witness(libff::bit_vector(a_sk_bits256.to_vector()));

    consent_note anote(a_pk_bits256,rho_bits256,trap_r_bits256,studyid_bits64,choice);    
    input_note_g.generate_r1cs_witness(path, address_bits, anote);

    if (!pb.is_satisfied())
        return nullptr;

    return digest2hex(nullifier_digest->get_digest());
}


//================================================================================
template<typename FieldT, typename HashT>
noteconsent_out_gadget<FieldT, HashT>::noteconsent_out_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> &cm,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
{
    rho.allocate(pb, libzeth::ZETH_RHO_SIZE,   FMT(this->annotation_prefix, " rho"));
    trap_r.allocate(pb, libzeth::ZETH_R_SIZE,   FMT(this->annotation_prefix, " trap_r"));
    studyid.allocate(pb, ZKC_STUDYID_SIZE,      FMT(this->annotation_prefix, " studyid"));
    choice.allocate(pb, FMT(this->annotation_prefix, " choice"));
    a_pk.reset(new libsnark::digest_variable<FieldT>(pb, HashT::get_digest_len(), FMT(this->annotation_prefix, " a_pk")));
    cm_gag.reset(new comm_consent_gadget<FieldT, HashT>(pb, a_pk->bits, rho, trap_r, studyid, choice, cm));
}

template<typename FieldT, typename HashT>
void noteconsent_out_gadget<FieldT, HashT>::generate_r1cs_constraints()
{
    for (size_t i = 0; i < libzeth::ZETH_RHO_SIZE; i++)
        libsnark::generate_boolean_r1cs_constraint<FieldT>(this->pb, rho[i], FMT(this->annotation_prefix, " rho[%zu]", i));

    for (size_t i = 0; i < libzeth::ZETH_R_SIZE; i++)
        libsnark::generate_boolean_r1cs_constraint<FieldT>(this->pb, trap_r[i], FMT(this->annotation_prefix, " trap_r[%zu]", i));

    for (size_t i = 0; i < ZKC_STUDYID_SIZE; i++)
        libsnark::generate_boolean_r1cs_constraint<FieldT>(this->pb, studyid[i], FMT(this->annotation_prefix, " studyid[%zu]", i));

    libsnark::generate_boolean_r1cs_constraint<FieldT>(this->pb, choice, FMT(this->annotation_prefix, " choice"));

    a_pk->generate_r1cs_constraints();
    cm_gag->generate_r1cs_constraints();
}

template<typename FieldT, typename HashT>
void noteconsent_out_gadget<FieldT, HashT>::generate_r1cs_witness(const consent_note &note)
{
    note.rho.fill_variable_array(this->pb, rho);
    note.trap_r.fill_variable_array(this->pb, trap_r);
    note.studyid.fill_variable_array(this->pb, studyid);
    this->pb.val(choice) = note.choice ? FieldT::one() : FieldT::zero();

    note.a_pk.fill_variable_array(this->pb, a_pk->bits);
    cm_gag->generate_r1cs_witness();
}

template<typename FieldT, typename HashT>
std::string noteconsent_out_gadget<FieldT, HashT>::test(
            const std::string&  s_apk, 
            const std::string&  s_rho,
            const std::string&  s_trap_r,
            const std::string&  s_studyid,
            bool                choice)
{
    //Construct the circuit
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> cm;

    cm.allocate(pb, "cm");
    noteconsent_out_gadget<FieldT, HashT> output_note_g(pb, cm);
    output_note_g.generate_r1cs_constraints();
    //=======================================================

    //Compute witness
    libzeth::bits256 a_pk_bits256   = libzeth::bits256::from_hex(s_apk);
    libzeth::bits256 rho_bits256    = libzeth::bits256::from_hex(s_rho);
    libzeth::bits256 trap_r_bits256 = libzeth::bits256::from_hex(s_trap_r);
    libzeth::bits64 studyid_bits64  = libzeth::bits64::from_hex(s_studyid);

    consent_note anote(a_pk_bits256,rho_bits256,trap_r_bits256,studyid_bits64,choice);    
    output_note_g.generate_r1cs_witness(anote);

    if (!pb.is_satisfied())
        return nullptr;

    return FieldtoString<FieldT>(pb.val(cm));
}


}

#include "extra_consent_gadgets.tcc"

#endif //__EXTRA_CONSENT_GADGETS_TCC_