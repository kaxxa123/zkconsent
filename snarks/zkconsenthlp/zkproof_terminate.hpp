#ifndef __ZKPROOF_TERMINATE_HPP_
#define __ZKPROOF_TERMINATE_HPP_

#include "libzeth/circuits/safe_arithmetic.hpp"

namespace libzkconsent
{

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
class zkterminate_gadget : libsnark::gadget<FieldT>
{
    //Packed Inputs: nf, hsig, htag, residuals
    //Public Inputs: Packed Inputs + mkroot
    static const size_t PCK_INPUTS = 4;
    static const size_t PUB_INPUTS = 5;

private:
    // Multipacking gadgets for the packed inputs
    std::array<libsnark::pb_variable_array<FieldT>, PCK_INPUTS>  packed_inputs;
    std::array<libsnark::pb_variable_array<FieldT>, PCK_INPUTS>  unpacked_inputs;
    std::array<std::shared_ptr<libsnark::multipacking_gadget<FieldT>>,PCK_INPUTS> packers;

    libsnark::pb_variable<FieldT> ZERO;
    std::shared_ptr<libsnark::pb_variable<FieldT>>      merkle_root;
    std::shared_ptr<libsnark::digest_variable<FieldT>>  input_nullifier;
    std::shared_ptr<libsnark::digest_variable<FieldT>>  hsig;
    std::shared_ptr<libsnark::digest_variable<FieldT>>  htag;
    std::shared_ptr<libsnark::digest_variable<FieldT>>  a_sk;
    
    std::shared_ptr<noteid_in_gadget<FieldT, HashT, HashTreeT, TreeDepth>>   input_notes;
    std::shared_ptr<libzeth::PRF_pk_gadget<FieldT, HashT>>       htag_gadget;

public:
    explicit zkterminate_gadget(
        libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix = "zkterminate_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness(
        const FieldT &rt,
        const zkc_input_note<FieldT, id_note, TreeDepth> &inputs,
        const libzeth::bits256 hsig_in);

    static bool test(
        const std::string&  s_ask, 
        const std::string&  s_rho,
        const std::string&  s_hsig,
        size_t              mkAddr);        
};

}

#include "zkproof_terminate.tcc"

#endif //__ZKPROOF_TERMINATE_HPP_
