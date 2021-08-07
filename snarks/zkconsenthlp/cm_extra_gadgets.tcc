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
std::string comm_id_gadget<FieldT, HashT>::get_cm(
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
    apk.allocate(pb, libzeth::ZETH_A_PK_SIZE, "a_pk");
    rho.allocate(pb, libzeth::ZETH_RHO_SIZE, "rho");

    comm_id_gadget<FieldT, HashT>  comm_id(pb, apk, rho, cm);
    comm_id.generate_r1cs_constraints();

    apk.fill_with_bits(pb, a_pk_bits256.to_vector());
    rho.fill_with_bits(pb, rho_bits256.to_vector());
    comm_id.generate_r1cs_witness();

    if (!pb.is_satisfied())
        return nullptr;

    return FieldtoString<FieldT>(pb.val(cm));
}

template<typename FieldT, typename HashT>
comm_consent_gadget<FieldT, HashT>::comm_consent_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable_array<FieldT> &a_pk,
    const libsnark::pb_variable_array<FieldT> &rho,
    const libsnark::pb_variable_array<FieldT> &trap_r,
    const libsnark::pb_variable_array<FieldT> &studyid,
    const libsnark::pb_variable<FieldT>       &choice,
    libsnark::pb_variable<FieldT> result,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , a_pk(a_pk)
    , rho(rho)
    , trap_r(trap_r)
    , studyid(studyid)
    , choice(choice)
{
    // Allocate temporary variable
    input.allocate(
        pb,
        ZKC_STUDYID_SIZE + ZKC_CHOICE_SIZE + 2 * HashT::get_digest_len(),
        FMT(this->annotation_prefix, " cm_input"));

    temp_result.reset(new libsnark::digest_variable<FieldT>(
        pb,
        HashT::get_digest_len(),
        FMT(this->annotation_prefix, " cm_temp_output")));

    // Allocate gadgets
    com_gadget.reset(new libzeth::COMM_gadget<FieldT, HashT>(
        pb, trap_r, input, temp_result, annotation_prefix));

    // This gadget casts the `temp_result` from bits to field element
    // We reverse the order otherwise the resulting linear combination is built
    // by interpreting our bit string as little endian.
    bits_to_field.reset(new libsnark::packing_gadget<FieldT>(
        pb,
        libsnark::pb_variable_array<FieldT>(
            temp_result->bits.rbegin(), temp_result->bits.rend()),
        result,
        FMT(this->annotation_prefix, " cm_bits_to_field")));
}

template<typename FieldT, typename HashT>
void comm_consent_gadget<FieldT, HashT>::generate_r1cs_constraints()
{
    com_gadget->generate_r1cs_constraints();

    // Flag set to true, to check booleaness of `final_k`
    bits_to_field->generate_r1cs_constraints(true);
}

template<typename FieldT, typename HashT>
void comm_consent_gadget<FieldT, HashT>::generate_r1cs_witness()
{
    //Consturct the input variable as 
    //input = apk || rho || studyid || choice
    std::vector<bool> temp;
    std::vector<bool> apk_bits = a_pk.get_bits(this->pb);
    temp.insert(temp.end(), apk_bits.begin(), apk_bits.end());
    std::vector<bool> rho_bits = rho.get_bits(this->pb);
    temp.insert(temp.end(), rho_bits.begin(), rho_bits.end());
    std::vector<bool> s_bits = studyid.get_bits(this->pb);
    temp.insert(temp.end(), s_bits.begin(), s_bits.end());

    libzeth::bits<8> choice_bits = (this->pb.val(choice) == FieldT::zero()) 
                                            ? libzeth::bits<8>::from_hex("00")
                                            : libzeth::bits<8>::from_hex("01");
    temp.insert(temp.end(), choice_bits.begin(), choice_bits.end());

    input.fill_with_bits(this->pb, temp);

    com_gadget->generate_r1cs_witness();
    bits_to_field->generate_r1cs_witness_from_bits();
}

template<typename FieldT, typename HashT>
std::string comm_consent_gadget<FieldT, HashT>::get_cm(
        const std::string& sapk, 
        const std::string& srho,
        const std::string& strap_r,
        const std::string& sid,
        bool bChoice)
{
    libzeth::bits256 a_pk_bits256    = libzeth::bits256::from_hex(sapk);
    libzeth::bits256 rho_bits256     = libzeth::bits256::from_hex(srho);
    libzeth::bits256 trap_r_bits256  = libzeth::bits256::from_hex(strap_r);
    libzeth::bits64  studyid_bits64  = libzeth::bits64::from_hex(sid);

    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> cm;
    libsnark::pb_variable_array<FieldT> apk;
    libsnark::pb_variable_array<FieldT> rho;
    libsnark::pb_variable_array<FieldT> trap_r;
    libsnark::pb_variable_array<FieldT> studyid;
    libsnark::pb_variable<FieldT>  choice;

    cm.allocate(pb, "cm");
    apk.allocate(pb, libzeth::ZETH_A_PK_SIZE, "a_pk");
    rho.allocate(pb, libzeth::ZETH_RHO_SIZE,  "rho");
    trap_r.allocate(pb, libzeth::ZETH_R_SIZE, "trap_r");
    studyid.allocate(pb, ZKC_STUDYID_SIZE,  "studyid");
    choice.allocate(pb, "choice");

    comm_consent_gadget<FieldT, HashT>  comm_id(pb, apk, rho, trap_r, studyid, choice, cm);
    comm_id.generate_r1cs_constraints();

    apk.fill_with_bits(pb, a_pk_bits256.to_vector());
    rho.fill_with_bits(pb, rho_bits256.to_vector());
    trap_r.fill_with_bits(pb, trap_r_bits256.to_vector());
    studyid.fill_with_bits(pb, studyid_bits64.to_vector());
    pb.val(choice) = bChoice ? FieldT::one() : FieldT::zero();
    comm_id.generate_r1cs_witness();

    if (!pb.is_satisfied())
        return nullptr;

    return FieldtoString<FieldT>(pb.val(cm));
}


}

#endif //__ZKC_COMM_TCC_