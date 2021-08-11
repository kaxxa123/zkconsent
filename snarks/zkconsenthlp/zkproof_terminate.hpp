#ifndef __ZKPROOF_TERMINATE_HPP_
#define __ZKPROOF_TERMINATE_HPP_

#include "libzeth/circuits/safe_arithmetic.hpp"

namespace libzkconsent
{

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
class zkterminate_gadget : libsnark::gadget<FieldT>
{
private:
    const size_t digest_len_minus_field_cap =   
        subtract_with_clamp(HashT::get_digest_len(), FieldT::capacity());

    // Number of residual bits from packing of hash digests into smaller
    // field elements: digest_len_minus_field_cap*(hsig + htag + nf)
    const size_t length_bit_residual =  digest_len_minus_field_cap*3;

    // Multipacking gadgets for the inputs (nullifierS, hsig, htag, residuals)
    std::array<libsnark::pb_variable_array<FieldT>, 4> packed_inputs;
    std::array<libsnark::pb_variable_array<FieldT>, 4> unpacked_inputs;
    std::array<std::shared_ptr<libsnark::multipacking_gadget<FieldT>>,4> packers;

    libsnark::pb_variable<FieldT> ZERO;
    std::shared_ptr<libsnark::pb_variable<FieldT>>      merkle_root;
    std::shared_ptr<libsnark::digest_variable<FieldT>>  input_nullifier;
    std::shared_ptr<libsnark::digest_variable<FieldT>>  h_sig;
    std::shared_ptr<libsnark::digest_variable<FieldT>>  h_is;
    std::shared_ptr<libsnark::digest_variable<FieldT>>  a_sk;
    
    std::shared_ptr<noteid_in_gadget<FieldT, HashT, HashTreeT, TreeDepth>>   input_notes;
    std::shared_ptr<libzeth::PRF_pk_gadget<FieldT, HashT>>       h_i_gadgets;

public:
    explicit zkterminate_gadget(
        libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix = "zkterminate_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness(
        const FieldT &rt,
        const zkc_input_note<FieldT, id_note, TreeDepth> &inputs,
        const libzeth::bits256 h_sig_in);    
};

}

#include "zkproof_terminate.tcc"

#endif //__ZKPROOF_TERMINATE_HPP_
