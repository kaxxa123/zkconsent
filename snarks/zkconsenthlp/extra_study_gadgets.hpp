#ifndef __EXTRA_STUDY_GADGETS_HPP_
#define __EXTRA_STUDY_GADGETS_HPP_

namespace libzkconsent
{

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
class study_in_gadget : public libsnark::gadget<FieldT>
{
private:
    //mktree leaf
    libsnark::pb_variable_array<FieldT>                         studyid;
    std::shared_ptr<libsnark::dual_variable_gadget<FieldT>>     studyidpck;

    //Make sure studyid != 0
    std::shared_ptr<libsnark::disjunction_gadget<FieldT>>       study_zero_gag;
    libsnark::pb_variable<FieldT>                               study_not_zero;

    // mktree_address - Address (left/right flags) of the commitment on the tree as Field
    // mktree_path    - Sibbling Hashes from leaf to root
    // mktree_gag     - Gadget for computing mkroot
    const libsnark::pb_variable<FieldT>                  mktree_root;
    libsnark::pb_variable_array<FieldT>                  mktree_address;
    std::shared_ptr<libsnark::pb_variable_array<FieldT>> mktree_path;
    std::shared_ptr<libzeth::merkle_path_compute<FieldT, HashTreeT>> mktree_gag;

    // nf_gag   - Computes nullifier from studyid and a_sk
    std::shared_ptr<PRF_nf_sid_gadget<FieldT, HashT>>   nf_gag;

public:
    study_in_gadget(
        libsnark::protoboard<FieldT>        &pb,
        const libsnark::pb_variable<FieldT> &ZERO,
        const libsnark::pb_variable<FieldT> &expected_root,
        std::shared_ptr<libsnark::digest_variable<FieldT>> a_sk,
        std::shared_ptr<libsnark::digest_variable<FieldT>> nullifier,
        const std::string &annotation_prefix = "study_in_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness(
        const std::vector<FieldT> &merkle_path,
        const libzeth::bits_addr<TreeDepth> &merkle_address,
        const libzeth::bits64& studyid_in);

    static std::string test(
        const std::string&  s_ask, 
        const std::string&  s_studyid,
        size_t              mkAddr);
};

}

#include "extra_study_gadgets.tcc"

#endif //__EXTRA_STUDY_GADGETS_HPP_