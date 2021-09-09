// SPDX-License-Identifier: LGPL-3.0+

#ifndef __EXTRA_CM_GADGETS_HPP_
#define __EXTRA_CM_GADGETS_HPP_

namespace libzkconsent
{

// Just like in ZETH commitments are simply
// the hash of a set of appended values:
// cm_id = Hash (apk || rho)
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

    static std::string get_cm(const std::string& a_pk, const std::string& rho);
};

//The consent commitment is a customization of the ZETH token commitment
//where we 1) Replace value by studyid
//         2) Add the ON/OFF consent flag (choice)
template<typename FieldT, typename HashT>
class comm_consent_gadget : public libsnark::gadget<FieldT>
{
private:
    // input variable
    libsnark::pb_variable_array<FieldT> input;
    libsnark::pb_variable_array<FieldT> a_pk;
    libsnark::pb_variable_array<FieldT> rho;
    libsnark::pb_variable_array<FieldT> trap_r;
    libsnark::pb_variable_array<FieldT> studyid;
    libsnark::pb_variable<FieldT>       choice;
    std::shared_ptr<libsnark::digest_variable<FieldT>> temp_result;

    // Hash gadgets used as inner, outer and final commitments
    std::shared_ptr<libzeth::COMM_gadget<FieldT, HashT>> com_gadget;

    // Packing gadget to output field element
    std::shared_ptr<libsnark::packing_gadget<FieldT>> bits_to_field;

public:
    comm_consent_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable_array<FieldT> &a_pk,
        const libsnark::pb_variable_array<FieldT> &rho,
        const libsnark::pb_variable_array<FieldT> &trap_r,
        const libsnark::pb_variable_array<FieldT> &studyid,
        const libsnark::pb_variable<FieldT>       &choice,
        libsnark::pb_variable<FieldT> result,
        const std::string &annotation_prefix = "comm_consent_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness();

    static std::string get_cm(
        const std::string& sapk, 
        const std::string& srho,
        const std::string& strap_r,
        const std::string& sid,
        bool bChoice);
};


}

#include "extra_cm_gadgets.tcc"

#endif //__EXTRA_CM_GADGETS_HPP_