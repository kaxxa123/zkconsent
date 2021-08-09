#ifndef __EXTRA_NOTE_GADGETS_HPP_
#define __EXTRA_NOTE_GADGETS_HPP_

namespace libzkconsent
{

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
class noteid_in_gadget : public libsnark::gadget<FieldT>
{
private:
    //id_note
    std::shared_ptr<libsnark::digest_variable<FieldT>> a_pk;
    libsnark::pb_variable_array<FieldT> rho;

    //Commitment gadget and commitment output
    std::shared_ptr<comm_id_gadget<FieldT, HashT>> cm_gag;
    libsnark::pb_variable<FieldT> cm;

    // mktree_address - Address (left/right flags) of the commitment on the tree as Field
    // mktree_path    - Sibbling Hashes from leaf to root
    // mktree_gag     - Gadget for computing mkroot
    const libsnark::pb_variable<FieldT>                  mktree_root;
    libsnark::pb_variable_array<FieldT>                  mktree_address;
    std::shared_ptr<libsnark::pb_variable_array<FieldT>> mktree_path;
    std::shared_ptr<libzeth::merkle_path_compute<FieldT, HashTreeT>> mktree_gag;

    // a_pk_gag - Makes sure the a_pk is computed corectly from a_sk
    // nf_gag   - Makes sure the nullifiers are computed correctly from rho and a_sk
    std::shared_ptr<libzeth::PRF_addr_a_pk_gadget<FieldT, HashT>> a_pk_gag;
    std::shared_ptr<libzeth::PRF_nf_gadget<FieldT, HashT>>  nf_gag;

public:
    noteid_in_gadget(
        libsnark::protoboard<FieldT>        &pb,
        const libsnark::pb_variable<FieldT> &ZERO,
        const libsnark::pb_variable<FieldT> &expected_root,
        std::shared_ptr<libsnark::digest_variable<FieldT>> a_sk,
        std::shared_ptr<libsnark::digest_variable<FieldT>> nullifier,
        const std::string &annotation_prefix = "noteid_in_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness(
        const std::vector<FieldT> &merkle_path,
        const libzeth::bits_addr<TreeDepth> &merkle_address,
        const id_note &note);

    static std::string test(
        const std::string&  s_ask, 
        const std::string&  s_rho,
        size_t              mkAddr);
};

template<typename FieldT, typename HashT>
class noteid_out_gadget : public libsnark::gadget<FieldT>
{
private:
    std::shared_ptr<libsnark::digest_variable<FieldT>> a_pk;
    std::shared_ptr<comm_id_gadget<FieldT, HashT>> cm_gag;

public:
    noteid_out_gadget(
        libsnark::protoboard<FieldT> &pb,
        std::shared_ptr<libsnark::digest_variable<FieldT>> rho,
        const libsnark::pb_variable<FieldT> &cm,
        const std::string &annotation_prefix = "noteid_out_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness(const id_note &note);

    static std::string test(
        const std::string&  s_apk, 
        const std::string&  s_rho);
};

}

#include "extra_note_gadgets.tcc"

#endif //__EXTRA_NOTE_GADGETS_HPP_