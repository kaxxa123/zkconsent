#ifndef __ZKC_CM_HPP_
#define __ZKC_CM_HPP_

namespace libzkconsent
{

std::string     CMMid(const std::string& a_pk, const std::string& rho);

std::string     CMMconsent(
                    const std::string& sapk, 
                    const std::string& srho,
                    const std::string& sr,
                    const std::string& sid,
                    bool bChoice);

std::string      FieldBound(const std::string& value);

}

#endif //__ZKC_CM_HPP_