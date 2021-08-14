#ifndef __EXTRA_STUDY_GADGETS_HPP_
#define __EXTRA_STUDY_GADGETS_HPP_

namespace libzkconsent
{

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
class study_valid_gadget : public libsnark::gadget<FieldT>
{
private:
    //Study Id is a Merkle Tree leaf value.
    //We generate this by packing the studyid bits with studyidpck
    //We also require extra validation to ensure studyid != 0
    libsnark::pb_variable<FieldT>                               study_not_zero;
    std::shared_ptr<libsnark::disjunction_gadget<FieldT>>       study_zero_gag;
    std::shared_ptr<libsnark::dual_variable_gadget<FieldT>>     studyidpck;

    // mktree_address - Address (left/right flags) of the commitment on the tree as Field
    // mktree_path    - Sibbling Hashes from leaf to root
    // mktree_gag     - Gadget for computing mkroot
    const libsnark::pb_variable<FieldT>                         mktree_root;
    libsnark::pb_variable_array<FieldT>                         mktree_address;
    std::shared_ptr<libsnark::pb_variable_array<FieldT>>        mktree_path;
    std::shared_ptr<libzeth::merkle_path_compute<FieldT, HashTreeT>> mktree_gag;

public:
    study_valid_gadget(
            libsnark::protoboard<FieldT>                &pb,
            const libsnark::pb_variable<FieldT>         &expected_root,
            const libsnark::pb_variable_array<FieldT>   &studyid,
            const std::string &annotation_prefix = "study_valid_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness(
            const std::vector<FieldT> &merkle_path,
            const libzeth::bits_addr<TreeDepth> &merkle_address);

    static bool test(
            const std::string&  s_ask, 
            const std::string&  s_studyid,
            size_t              mkAddr);
};

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
class study_in_gadget : public libsnark::gadget<FieldT>
{
private:
    // studyval_gag - Study Id validity and Merkle Tree memebership 
    std::shared_ptr<study_valid_gadget<FieldT, HashT, HashTreeT, TreeDepth>> 
                studyval_gag;

    // nf_gag - Computes nullifier from studyid and a_sk
    std::shared_ptr<PRF_nf_sid_gadget<FieldT, HashT>>
                nf_gag;

public:
    study_in_gadget(
        libsnark::protoboard<FieldT>                &pb,
        const libsnark::pb_variable<FieldT>         &ZERO,
        const libsnark::pb_variable<FieldT>         &expected_root,
        const libsnark::pb_variable_array<FieldT>   &studyid,
        std::shared_ptr<libsnark::digest_variable<FieldT>> a_sk,
        std::shared_ptr<libsnark::digest_variable<FieldT>> nullifier,
        const std::string &annotation_prefix = "study_in_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness(
        const std::vector<FieldT> &merkle_path,
        const libzeth::bits_addr<TreeDepth> &merkle_address);

    static std::string test(
        const std::string&  s_ask, 
        const std::string&  s_studyid,
        size_t              mkAddr);
};

}

#include "extra_study_gadgets.tcc"

#endif //__EXTRA_STUDY_GADGETS_HPP_