#ifndef __ZKPROOF_MINT_HPP_
#define __ZKPROOF_MINT_HPP_

#include "libzeth/circuits/safe_arithmetic.hpp"

namespace libzkconsent
{

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
class zkmint_gadget : libsnark::gadget<FieldT>
{
    //Packed Inputs: 2*nf, hsig, htag, residuals
    //Public Inputs: Packed Inputs + 2*cm + mkrootId + mkrootStudy
    static const size_t PCK_INPUTS = 5;
    static const size_t PUB_INPUTS = 9;

private:
    // Multipacking gadgets for the packed inputs
    std::array<libsnark::pb_variable_array<FieldT>, PCK_INPUTS>  packed_inputs;
    std::array<libsnark::pb_variable_array<FieldT>, PCK_INPUTS>  unpacked_inputs;
    std::array<std::shared_ptr<libsnark::multipacking_gadget<FieldT>>,PCK_INPUTS> packers;

    libsnark::pb_variable<FieldT> ZERO;
    std::shared_ptr<libsnark::pb_variable<FieldT>>                      mkroot_id;
    std::shared_ptr<libsnark::pb_variable<FieldT>>                      mkroot_study;
    std::shared_ptr<libsnark::digest_variable<FieldT>>                  nf_id;
    std::shared_ptr<libsnark::digest_variable<FieldT>>                  nf_study;
    libsnark::pb_variable<FieldT>                                       cm_id;
    libsnark::pb_variable<FieldT>                                       cm_consent;
    libsnark::pb_variable_array<FieldT>                                 studyid;
    libsnark::pb_variable<FieldT>                                       choice;
    std::shared_ptr<libsnark::digest_variable<FieldT>>                  hsig;
    std::shared_ptr<libsnark::digest_variable<FieldT>>                  htag;
    std::shared_ptr<libsnark::digest_variable<FieldT>>                  a_sk;

    std::shared_ptr<noteid_in_gadget<FieldT, HashT, HashTreeT, TreeDepth>>      noteIdIn_gag;
    std::shared_ptr<study_in_gadget<FieldT, HashT, HashTreeT, TreeDepth>>       study_gag;
    std::shared_ptr<libzeth::PRF_pk_gadget<FieldT, HashT>>                      htag_gag;
    std::shared_ptr<noteid_out_gadget<FieldT, HashT>>                           noteIdOut_gag;
    std::shared_ptr<noteconsent_out_gadget<FieldT, HashT>>                      noteConsentOut_gag;

public:
    explicit zkmint_gadget(
        libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix = "zkterminate_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
        // const FieldT &rt,
        // const zkc_input_note<FieldT, id_note, TreeDepth> &inputs,
        // const libzeth::bits256 h_sig_in);

    static bool test();
        // const std::string&  s_ask, 
        // const std::string&  s_rho,
        // const std::string&  s_hsig,
        // size_t              mkAddr);        
};

}

#include "zkproof_mint.tcc"

#endif //__ZKPROOF_MINT_HPP_
