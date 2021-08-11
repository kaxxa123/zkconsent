
#ifndef __ZKC_HELPERS_HPP_
#define __ZKC_HELPERS_HPP_


namespace libzkconsent
{

std::string     digest2hex(const std::vector<bool>& digest);

template<typename FieldT>    
std::string     FieldtoString(FieldT& value)
{
    std::ostringstream ss;
    ss << value;
    return ss.str();
}

// Also checkout from libzeth namespace
// template<typename FieldT>
// std::string base_field_element_to_hex(const FieldT &field_el)
// template<typename FieldT>
// FieldT base_field_element_from_hex(const std::string &hex)

template<typename FieldT>    
void digest_variable_assign_to_field_element_and_residual(
    const libsnark::digest_variable<FieldT> &digest_var,
    libsnark::pb_variable_array<FieldT> &unpacked_element,
    libsnark::pb_variable_array<FieldT> &unpacked_residual_bits)
{
    const size_t field_capacity = FieldT::capacity();

    unpacked_element.insert(
        unpacked_element.end(),
        digest_var.bits.rbegin(),
        digest_var.bits.rbegin() + field_capacity);

    unpacked_residual_bits.insert(
        unpacked_residual_bits.end(),
        digest_var.bits.rbegin() + field_capacity,
        digest_var.bits.rend());
}

}

    

#endif //__ZKC_HELPERS_HPP_