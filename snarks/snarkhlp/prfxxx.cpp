#include <stdlib.h>
#include <iostream>

#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/circuits/prfs/prf.hpp"
#include "libzeth/core/utils.hpp"
#include "libzeth/zeth_constants.hpp"

#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"

using pp = libsnark::default_r1cs_ppzksnark_pp;
using FieldT = libff::Fr<pp>;
using HashT = libzeth::BLAKE2s_256<FieldT>;

static std::string digest2hex(const std::vector<bool>& digest)
{
    std::string strOut;

    //digest is made up of a sequence of bytes hence
    //the size must be a factor of 8
    if (digest.size() % 8)
        return strOut;

    for (size_t pos = 0; pos+3 < digest.size(); pos += 4)
    {
        uint fourBits = digest[pos] ? 8 : 0;
        fourBits += digest[pos + 1] ? 4 : 0;
        fourBits += digest[pos + 2] ? 2 : 0;
        fourBits += digest[pos + 3] ? 1 : 0;
        
        if (fourBits < 10)
                strOut += (char)('0'+fourBits); 
        else    strOut += (char)('A'+fourBits-10);    
    }

    return strOut;
}

//Test Values
//ask = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"
//apk = "2390c9e5370be7355f220b29caf3912ef970d828b73976ae9bfeb1402ce4c1f9"
std::string     PRFapk(const char* szAsk)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    libsnark::pb_variable_array<FieldT> a_sk;

    libzeth::bits256 a_sk_bits256 = libzeth::bits256::from_hex(szAsk);

    std::shared_ptr<libsnark::digest_variable<FieldT>> result(
        new libsnark::digest_variable<FieldT>(pb, HashT::get_digest_len(), "result"));
        
    ZERO.allocate(pb, "zero");
    a_sk.allocate(pb, libzeth::ZETH_A_SK_SIZE, "a_sk");
    libzeth::PRF_addr_a_pk_gadget<FieldT, HashT> prf_apk_gadget(pb, ZERO, a_sk, result);

    prf_apk_gadget.generate_r1cs_constraints();

    pb.val(ZERO) = FieldT::zero();
    a_sk.fill_with_bits(pb, a_sk_bits256.to_vector());
    prf_apk_gadget.generate_r1cs_witness();

    if (!pb.is_satisfied())
        return NULL;

    return digest2hex(result->get_digest());
}

//Test Values
//ask = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"
//rho = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF"
//nf  = "ea43866d185e1bdb84713b699a2966d929d1392488c010c603e46a4cb92986f8"
std::string     PRFnf(const char* szAsk, const char* szRho)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    libsnark::pb_variable_array<FieldT> a_sk;
    libsnark::pb_variable_array<FieldT> rho;

    libzeth::bits256 a_sk_bits256 = libzeth::bits256::from_hex(szAsk);
    libzeth::bits256 rho_bits256  = libzeth::bits256::from_hex(szRho);

    std::shared_ptr<libsnark::digest_variable<FieldT>> result(
        new libsnark::digest_variable<FieldT>(pb, HashT::get_digest_len(), "result"));

    ZERO.allocate(pb, "zero");
    a_sk.allocate(pb, libzeth::ZETH_A_SK_SIZE, "a_sk");
    rho.allocate(pb, libzeth::ZETH_RHO_SIZE, "rho");

    libzeth::PRF_nf_gadget<FieldT, HashT> prf_nf_gadget(pb, ZERO, a_sk, rho, result);
    prf_nf_gadget.generate_r1cs_constraints();

    pb.val(ZERO) = FieldT::zero();
    a_sk.fill_with_bits(pb, a_sk_bits256.to_vector());
    rho.fill_with_bits(pb, rho_bits256.to_vector());
    prf_nf_gadget.generate_r1cs_witness();

    if (!pb.is_satisfied())
        return NULL;

    return digest2hex(result->get_digest());
}
