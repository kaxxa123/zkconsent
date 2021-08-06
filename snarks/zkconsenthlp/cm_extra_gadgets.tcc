#ifndef __ZKC_COMM_TCC_
#define __ZKC_COMM_TCC_

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>

namespace libzkconsent
{

template<typename FieldT, typename HashT>
comm_id_gadget<FieldT, HashT>::comm_id_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable_array<FieldT> &a_pk,
    const libsnark::pb_variable_array<FieldT> &rho,
    libsnark::pb_variable<FieldT> result,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
{
    block.reset(new libsnark::block_variable<FieldT>(
        pb, {a_pk, rho}, FMT(this->annotation_prefix, " block")));

    bits_result.reset(new libsnark::digest_variable<FieldT>(
        pb,
        HashT::get_digest_len(),
        FMT(this->annotation_prefix, " cm_output_bits")));

    hasher.reset(new HashT(
        pb, *block, *bits_result, FMT(this->annotation_prefix, " hasher_gadget")));

    bits_to_field.reset(new libsnark::packing_gadget<FieldT>(
        pb,
        libsnark::pb_variable_array<FieldT>(
            bits_result->bits.rbegin(), bits_result->bits.rend()),
        result,
        FMT(this->annotation_prefix, " cm_field")));
}

template<typename FieldT, typename HashT>
void comm_id_gadget<FieldT, HashT>::generate_r1cs_constraints()
{
    // ensure_output_bitness set to true
    hasher->generate_r1cs_constraints(true);

    // Flag set to true, to check booleaness of `final_k`
    bits_to_field->generate_r1cs_constraints(true);
}

template<typename FieldT, typename HashT>
void comm_id_gadget<FieldT, HashT>::generate_r1cs_witness()
{
    hasher->generate_r1cs_witness();
    bits_to_field->generate_r1cs_witness_from_bits();
}

template<typename FieldT, typename HashT>
std::string comm_id_gadget<FieldT, HashT>::get_id_comm(
    const std::string& sapk, 
    const std::string& srho)
{
    libzeth::bits256 a_pk_bits256 = libzeth::bits256::from_hex(sapk);
    libzeth::bits256 rho_bits256  = libzeth::bits256::from_hex(srho);

    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> cm;
    libsnark::pb_variable_array<FieldT> apk;
    libsnark::pb_variable_array<FieldT> rho;

    cm.allocate(pb, "cm");
    apk.allocate(pb, 256UL, "a_pk");
    rho.allocate(pb, 256UL, "rho");

    comm_id_gadget<FieldT, HashT>  comm_id(pb, apk, rho, cm);
    comm_id.generate_r1cs_constraints();

    apk.fill_with_bits(pb, a_pk_bits256.to_vector());
    rho.fill_with_bits(pb, rho_bits256.to_vector());
    comm_id.generate_r1cs_witness();

    if (!pb.is_satisfied())
        return nullptr;

    return FieldtoString<FieldT>(pb.val(cm));
}

}

#endif //__ZKC_COMM_TCC_