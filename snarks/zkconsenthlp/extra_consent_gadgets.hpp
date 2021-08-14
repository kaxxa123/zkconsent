#ifndef __EXTRA_CONSENT_GADGETS_HPP_
#define __EXTRA_CONSENT_GADGETS_HPP_

namespace libzkconsent
{

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
class noteconsent_in_gadget : public libsnark::gadget<FieldT>
{
private:
    libsnark::pb_variable_array<FieldT> trap_r;
    libsnark::pb_variable_array<FieldT> rho;
    std::shared_ptr<comm_consent_gadget<FieldT, HashT>> cm_gag;
    libsnark::pb_variable<FieldT> cm;

    // mktree_address - Address (left/right flags) of the commitment on the tree as Field
    // mktree_path    - Sibbling Hashes from leaf to root
    // mktree_gag     - Gadget for computing mkroot
    const libsnark::pb_variable<FieldT>                  mktree_root;
    libsnark::pb_variable_array<FieldT>                  mktree_address;
    std::shared_ptr<libsnark::pb_variable_array<FieldT>> mktree_path;
    std::shared_ptr<libzeth::merkle_path_compute<FieldT, HashTreeT>> mktree_gag;

    // nf_gag   - Computes nullifier from rho and a_sk
    std::shared_ptr<libzeth::PRF_nf_gadget<FieldT, HashT>>  nf_gag;

public:
    noteconsent_in_gadget(
        libsnark::protoboard<FieldT>        &pb,
        const libsnark::pb_variable<FieldT> &ZERO,
        const libsnark::pb_variable<FieldT> &expected_root,
        std::shared_ptr<libsnark::digest_variable<FieldT>> a_sk,
        std::shared_ptr<libsnark::digest_variable<FieldT>> a_pk,
        const libsnark::pb_variable_array<FieldT>  &studyid,
        const libsnark::pb_variable<FieldT> &choice,
        std::shared_ptr<libsnark::digest_variable<FieldT>> nullifier,
        const std::string &annotation_prefix = "noteconsent_in_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness(
        const std::vector<FieldT> &merkle_path,
        const libzeth::bits_addr<TreeDepth> &merkle_address,
        const libzeth::bits256& rho_bits256,
        const libzeth::bits256& trap_r_bits256);

    static std::string test(
        const std::string&  s_ask, 
        const std::string&  s_rho,
        const std::string&  s_trap_r,
        const std::string&  s_studyid,
        bool                choice_in,
        size_t              mkAddr);
};

template<typename FieldT, typename HashT>
class noteconsent_out_gadget : public libsnark::gadget<FieldT>
{
private:
    libsnark::pb_variable_array<FieldT> trap_r;
    libsnark::pb_variable_array<FieldT> rho;
    std::shared_ptr<comm_consent_gadget<FieldT, HashT>> cm_gag;

public:
    noteconsent_out_gadget(
        libsnark::protoboard<FieldT> &pb,
        std::shared_ptr<libsnark::digest_variable<FieldT>> a_pk,
        const libsnark::pb_variable_array<FieldT>  &studyid,
        const libsnark::pb_variable<FieldT> &choice,
        const libsnark::pb_variable<FieldT> &cm,
        const std::string &annotation_prefix = "noteconsent_out_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness(
        const libzeth::bits256& rho_bits256,
        const libzeth::bits256& trap_r_bits256);

    static std::string test(
        const std::string&  s_apk, 
        const std::string&  s_rho,
        const std::string&  s_trap_r,
        const std::string&  s_studyid,
        bool                choice_in);
};

}

#include "extra_consent_gadgets.tcc"

#endif //__EXTRA_CONSENT_GADGETS_HPP_