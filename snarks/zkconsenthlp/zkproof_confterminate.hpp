// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZKPROOF_CONFTERMINATE_HPP_
#define __ZKPROOF_CONFTERMINATE_HPP_

namespace libzkconsent
{

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
class zkconfterminate_gadget : libsnark::gadget<FieldT>
{
private:
    //Public
    libsnark::pb_variable<FieldT>                           cm_identity;

    //Private
    libsnark::pb_variable<FieldT>                           ZERO;
    std::shared_ptr<libsnark::digest_variable<FieldT>>      a_pk;
    std::shared_ptr<noteid_out_gadget<FieldT, HashT>>       noteIdOut_gag;

public:
    explicit zkconfterminate_gadget(
        libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix = " zkconfterminate_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness(
        const libzeth::bits256      &apk_in,
        const libzeth::bits256      &rho_in);

    void generate_r1cs_witness_test(
        const std::string&  s_apk,
        const std::string&  s_rho);        

    static bool test(
        const std::string&  s_apk,
        const std::string&  s_rho);        
};

}

#include "zkproof_confterminate.tcc"

#endif //__ZKPROOF_CONFTERMINATE_HPP_
