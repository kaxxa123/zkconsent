
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

}


#endif //__ZKC_HELPERS_HPP_