#ifndef __ZKC_COMM_HPP_
#define __ZKC_COMM_HPP_

namespace libzkconsent
{

template<typename FieldT, typename HashT>
class comm_id_gadget : libsnark::gadget<FieldT>
{
private:
    // input variable block = {a_pk, rho}
    std::shared_ptr<libsnark::block_variable<FieldT>> block;

    // Hash gadget used as a commitment
    std::shared_ptr<HashT> hasher;

    // hash digest = HashT(a_pk || rho)
    std::shared_ptr<libsnark::digest_variable<FieldT>> bits_result;

    // Packing gadget to output result as field element
    std::shared_ptr<libsnark::packing_gadget<FieldT>>  bits_to_field;

public:
    comm_id_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable_array<FieldT> &a_pk,
        const libsnark::pb_variable_array<FieldT> &rho,
        libsnark::pb_variable<FieldT> result,
        const std::string &annotation_prefix = "comm_id_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness();

    static std::string get_id_comm(const std::string& a_pk, const std::string& rho);
};

}

#include "cm_extra_gadgets.tcc"

#endif //__ZKC_COMM_HPP_