
#ifndef __ZKCONSENT_PRFS_TCC__
#define __ZKCONSENT_PRFS_TCC__

#include "libzeth/circuits/prfs/prf.hpp"

namespace libzkconsent
{

template<typename FieldT>
libsnark::pb_variable_array<FieldT> get_tag_nf_uid(
    const libsnark::pb_variable<FieldT> &ZERO,
    const libsnark::pb_variable_array<FieldT> &a_sk)
{
    libsnark::pb_variable_array<FieldT> tagged_a_sk;
    tagged_a_sk.emplace_back(ONE);  // 1
    tagged_a_sk.emplace_back(ONE);  // 11
    tagged_a_sk.emplace_back(ZERO); // 110
    tagged_a_sk.emplace_back(ONE);  // 1101

    // Should always be satisfied because a_sk
    // is a 256 bit string. This is just a sanity check
    // to make sure that the for loop doesn't
    // go out of the bound of the a_sk vector
    assert(a_sk.size() > 252);
    for (size_t i = 0; i < 252; ++i) {
        tagged_a_sk.emplace_back(a_sk[i]);
    }

    // Check that we correctly built a 256-bit string
    assert(tagged_a_sk.size() == 256);

    return tagged_a_sk;
}

template<typename FieldT>
libsnark::pb_variable_array<FieldT> get_tag_nf_sid(
    const libsnark::pb_variable<FieldT> &ZERO,
    const libsnark::pb_variable_array<FieldT> &a_sk)
{
    libsnark::pb_variable_array<FieldT> tagged_a_sk;
    tagged_a_sk.emplace_back(ONE);  // 1
    tagged_a_sk.emplace_back(ONE);  // 11
    tagged_a_sk.emplace_back(ONE);  // 111
    tagged_a_sk.emplace_back(ONE);  // 1111

    // Should always be satisfied because a_sk
    // is a 256 bit string. This is just a sanity check
    // to make sure that the for loop doesn't
    // go out of the bound of the a_sk vector
    assert(a_sk.size() > 252);
    for (size_t i = 0; i < 252; ++i) {
        tagged_a_sk.emplace_back(a_sk[i]);
    }

    // Check that we correctly built a 256-bit string
    assert(tagged_a_sk.size() == 256);

    return tagged_a_sk;
}

// PRF to generate the nullifier
// nf = blake2sCompress(1101 || [a_sk]_252 || rho): See ZCash protocol
// specification paper, page 57
template<typename FieldT, typename HashT>
PRF_nf_uid_gadget<FieldT, HashT>::PRF_nf_uid_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> &ZERO,
    const libsnark::pb_variable_array<FieldT> &a_sk,
    const libsnark::pb_variable_array<FieldT> &rho,
    std::shared_ptr<libsnark::digest_variable<FieldT>> result,
    const std::string &annotation_prefix)
    : libzeth::PRF_gadget<FieldT, HashT>(
          pb, 
          get_tag_nf_uid(ZERO, a_sk), 
          rho, 
          result, 
          annotation_prefix)
{
}

// PRF to generate the nullifier
// nf = blake2sCompress(1111 || [a_sk]_252 || sid): See ZCash protocol
// specification paper, page 57
template<typename FieldT, typename HashT>
PRF_nf_sid_gadget<FieldT, HashT>::PRF_nf_sid_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> &ZERO,
    const libsnark::pb_variable_array<FieldT> &a_sk,
    const libsnark::pb_variable_array<FieldT> &sid,
    std::shared_ptr<libsnark::digest_variable<FieldT>> result,
    const std::string &annotation_prefix)
    : libzeth::PRF_gadget<FieldT, HashT>(
          pb, 
          get_tag_nf_sid(ZERO, a_sk), 
          sid, 
          result, 
          annotation_prefix)
{
}

// Helper function for generating nullifiers from  
// gadgets that take 2*256UL inputs
template<typename FieldT, typename HashT, typename GadgetT>
std::string     PRF_1input(
    const std::string& sOne)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    libsnark::pb_variable_array<FieldT> one;

    libzeth::bits256 one_bits256 = libzeth::bits256::from_hex(sOne);

    std::shared_ptr<libsnark::digest_variable<FieldT>> result(
        new libsnark::digest_variable<FieldT>(pb, HashT::get_digest_len(), "result"));
        
    ZERO.allocate(pb, "zero");
    one.allocate(pb, 256UL, "input_one");

    GadgetT prf_gadget(pb, ZERO, one, result);
    prf_gadget.generate_r1cs_constraints();

    pb.val(ZERO) = FieldT::zero();
    one.fill_with_bits(pb, one_bits256.to_vector());
    prf_gadget.generate_r1cs_witness();

    if (!pb.is_satisfied())
        return nullptr;

    return digest2hex(result->get_digest());
}

// Helper function for generating nullifiers from  
// gadgets that take 2*256UL inputs
template<typename FieldT, typename HashT, typename GadgetT>
std::string     PRF_2input(
    const std::string& sOne, 
    const std::string& sTwo)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    libsnark::pb_variable_array<FieldT> one;
    libsnark::pb_variable_array<FieldT> two;

    libzeth::bits256 one_bits256 = libzeth::bits256::from_hex(sOne);
    libzeth::bits256 two_bits256 = libzeth::bits256::from_hex(sTwo);

    std::shared_ptr<libsnark::digest_variable<FieldT>> result(
        new libsnark::digest_variable<FieldT>(pb, HashT::get_digest_len(), "result"));

    ZERO.allocate(pb, "zero");
    one.allocate(pb, 256UL, "input_one");
    two.allocate(pb, 256UL, "input_two");

    GadgetT prf_gadget(pb, ZERO, one, two, result);
    prf_gadget.generate_r1cs_constraints();

    pb.val(ZERO) = FieldT::zero();
    one.fill_with_bits(pb, one_bits256.to_vector());
    two.fill_with_bits(pb, two_bits256.to_vector());
    prf_gadget.generate_r1cs_witness();

    if (!pb.is_satisfied())
        return nullptr;

    return digest2hex(result->get_digest());
}

template<typename FieldT, typename HashT, typename GadgetT>
std::string     PRF_3input(
    const std::string& sOne, 
    const std::string& sTwo,
    size_t index)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    libsnark::pb_variable_array<FieldT> one;
    libsnark::pb_variable_array<FieldT> two;

    libzeth::bits256 one_bits256 = libzeth::bits256::from_hex(sOne);
    libzeth::bits256 two_bits256 = libzeth::bits256::from_hex(sTwo);

    std::shared_ptr<libsnark::digest_variable<FieldT>> result(
        new libsnark::digest_variable<FieldT>(pb, HashT::get_digest_len(), "result"));

    ZERO.allocate(pb, "zero");
    one.allocate(pb, 256UL, "input_one");
    two.allocate(pb, 256UL, "input_two");

    GadgetT prf_gadget(pb, ZERO, one, two, index, result);
    prf_gadget.generate_r1cs_constraints();

    pb.val(ZERO) = FieldT::zero();
    one.fill_with_bits(pb, one_bits256.to_vector());
    two.fill_with_bits(pb, two_bits256.to_vector());
    prf_gadget.generate_r1cs_witness();

    if (!pb.is_satisfied())
        return nullptr;

    return digest2hex(result->get_digest());}
}

#endif // __ZKCONSENT_PRFS_TCC__
