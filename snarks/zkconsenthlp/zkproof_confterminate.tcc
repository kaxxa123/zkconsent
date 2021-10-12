// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZKPROOF_CONFTERMINATE_TCC_
#define __ZKPROOF_CONFTERMINATE_TCC_

namespace libzkconsent
{

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
zkconfterminate_gadget<FieldT,HashT,HashTreeT,TreeDepth>::zkconfterminate_gadget(
        libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix)
        : libsnark::gadget<FieldT>(pb, annotation_prefix)
{
    // PUBLIC DATA: allocated first so that the protoboard has access.
    cm_identity.allocate(pb, FMT(this->annotation_prefix, " cm_identity"));

    // PRIVATE DATA:
    ZERO.allocate(pb, FMT(this->annotation_prefix, " ZERO"));
    a_pk.reset(new libsnark::digest_variable<FieldT>(pb,libzeth::ZETH_A_PK_SIZE,FMT(this->annotation_prefix, " a_pk")));

    // Gadget computing the commitment
    noteIdOut_gag.reset(new noteid_out_gadget<FieldT, HashT>(
                pb, a_pk, cm_identity));
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
void zkconfterminate_gadget<FieldT,HashT,HashTreeT,TreeDepth>::generate_r1cs_constraints()
{
    libsnark::generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), FMT(this->annotation_prefix, " ZERO"));

    a_pk->generate_r1cs_constraints();
    noteIdOut_gag->generate_r1cs_constraints();
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
void zkconfterminate_gadget<FieldT,HashT,HashTreeT,TreeDepth>::generate_r1cs_witness(
    const libzeth::bits256      &apk_in,
    const libzeth::bits256      &rho_in)
{
    //All boolean inputs are verified for "booleaness" as follows: 
    //  apk_in              in zkconfterminate_gadget::generate_r1cs_constraints()
    // 
    //  rho_in              in noteid_out_gadget::generate_r1cs_constraints()

    this->pb.val(ZERO) = FieldT::zero();
    a_pk->generate_r1cs_witness(apk_in.to_vector());

    noteIdOut_gag->generate_r1cs_witness(rho_in);
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
void zkconfterminate_gadget<FieldT,HashT,HashTreeT,TreeDepth>::generate_r1cs_witness_test(
    const std::string&  s_apk,
    const std::string&  s_rho)
{
    libzeth::bits256 a_pk_bits256       = libzeth::bits256::from_hex(s_apk);
    libzeth::bits256 rho_bits256        = libzeth::bits256::from_hex(s_rho);

    generate_r1cs_witness(a_pk_bits256, rho_bits256);
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
bool zkconfterminate_gadget<FieldT,HashT,HashTreeT,TreeDepth>::test(
        const std::string&  s_apk,
        const std::string&  s_rho)
{
    libsnark::protoboard<FieldT> pb;
    zkconfterminate_gadget<FieldT,HashT,HashTreeT,TreeDepth> confterminate_gag(pb);

    confterminate_gag.generate_r1cs_constraints();
    confterminate_gag.generate_r1cs_witness_test(s_apk, s_rho);

    return pb.is_satisfied();    
}

}


#endif //__ZKPROOF_CONFTERMINATE_TCC_
