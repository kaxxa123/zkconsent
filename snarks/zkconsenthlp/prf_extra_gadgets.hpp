
#ifndef __ZKCONSENT_PRFS_HPP__
#define __ZKCONSENT_PRFS_HPP__

// DISCLAIMER:
// Content Taken and adapted from ZETH

#include "libzeth/circuits/circuit_utils.hpp"

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>

namespace libzkconsent
{
template<typename FieldT>
libsnark::pb_variable_array<FieldT> get_tag_nf_uid(
    const libsnark::pb_variable<FieldT> &ZERO,
    const libsnark::pb_variable_array<FieldT> &a_sk);

template<typename FieldT>
libsnark::pb_variable_array<FieldT> get_tag_nf_sid(
    const libsnark::pb_variable<FieldT> &ZERO,
    const libsnark::pb_variable_array<FieldT> &a_sk);

template<typename FieldT, typename HashT, typename GadgetT>
std::string     PRF_1input_nfT(
    const std::string& sOne);

template<typename FieldT, typename HashT, typename GadgetT>
std::string     PRF_2input_nfT(
    const std::string& sOne, 
    const std::string& sTwo);

/// PRF to generate the nullifier for user id token
/// nf = blake2sCompress("1101" || [a_sk]_252 || rho): See ZCash protocol
/// specification paper, page 57
template<typename FieldT, typename HashT>
class PRF_nf_uid_gadget : public libzeth::PRF_gadget<FieldT, HashT>
{
public:
    PRF_nf_uid_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable<FieldT> &ZERO,
        const libsnark::pb_variable_array<FieldT> &a_sk,
        const libsnark::pb_variable_array<FieldT> &rho,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result,
        const std::string& annotation_prefix = "PRF_nf_uid_gadget");
};

/// PRF to generate the nullifier for study token minting
/// nf = blake2sCompress("1111" || [a_sk]_252 || sid): See ZCash protocol
/// specification paper, page 57
template<typename FieldT, typename HashT>
class PRF_nf_sid_gadget : public libzeth::PRF_gadget<FieldT, HashT>
{
public:
    PRF_nf_sid_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable<FieldT> &ZERO,
        const libsnark::pb_variable_array<FieldT> &a_sk,
        const libsnark::pb_variable_array<FieldT> &sid,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result,
        const std::string &annotation_prefix = "PRF_nf_sid_gadget");
};

}

#include "prf_extra_gadgets.tcc"

#endif // __ZKCONSENT_PRFS_HPP__
