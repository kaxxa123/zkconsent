// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZKPROOF_TERMINATE_HPP_
#define __ZKPROOF_TERMINATE_HPP_

#include "libzeth/circuits/safe_arithmetic.hpp"

namespace libzkconsent
{

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
class zkterminate_gadget : libsnark::gadget<FieldT>
{
public:
    //Packed Inputs: nf, hsig, htag, residuals
    //Public Inputs: Packed Inputs + cm + mkroot
    static const size_t PCK_INPUTS = 4;
    static const size_t PUB_INPUTS = 6;

private:
    // Multipacking gadgets for the packed inputs
    std::array<libsnark::pb_variable_array<FieldT>, PCK_INPUTS>  packed_inputs;
    std::array<libsnark::pb_variable_array<FieldT>, PCK_INPUTS>  unpacked_inputs;
    std::array<std::shared_ptr<libsnark::multipacking_gadget<FieldT>>,PCK_INPUTS> packers;

    libsnark::pb_variable<FieldT> ZERO;
    std::shared_ptr<libsnark::pb_variable<FieldT>>      mkroot_id;
    std::shared_ptr<libsnark::digest_variable<FieldT>>  nf_id;
    libsnark::pb_variable<FieldT>                       cm_id;
    std::shared_ptr<libsnark::digest_variable<FieldT>>  a_sk;
    std::shared_ptr<libsnark::digest_variable<FieldT>>  a_pk;
    std::shared_ptr<libsnark::digest_variable<FieldT>>  hsig;
    std::shared_ptr<libsnark::digest_variable<FieldT>>  htag;
    
    std::shared_ptr<libzeth::PRF_addr_a_pk_gadget<FieldT, HashT>>           a_pk_gag;
    std::shared_ptr<noteid_in_gadget<FieldT, HashT, HashTreeT, TreeDepth>>  noteIdIn_gag;
    std::shared_ptr<noteid_out_gadget<FieldT, HashT>>                       noteIdOut_gag;
    std::shared_ptr<libzeth::PRF_pk_gadget<FieldT, HashT>>                  htag_gadget;

public:
    explicit zkterminate_gadget(
        libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix = "zkterminate_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness(
        const libzeth::bits256      &ask_in,
        const FieldT                &mkrootId,
        const std::vector<FieldT>   &mkpathId,
        const libzeth::bits_addr<TreeDepth> &mkaddrId,
        const libzeth::bits256      &rhoId_in,
        const libzeth::bits256      &rhoId_out,
        const libzeth::bits256      &hsig_in);

    void generate_r1cs_witness_test(
        const std::string&  s_ask,
        size_t              mkaddrId, 
        const std::string&  s_rhoId_in,
        const std::string&  s_rhoId_out,
        const std::string&  s_hsig);

    static bool test(
        const std::string&  s_ask,
        size_t              mkaddrId, 
        const std::string&  s_rhoId_in,
        const std::string&  s_rhoId_out,
        const std::string&  s_hsig);
};

}

#include "zkproof_terminate.tcc"

#endif //__ZKPROOF_TERMINATE_HPP_
