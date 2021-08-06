#ifndef __ZKC_PRF_H_
#define __ZKC_PRF_H_

namespace libzkconsent
{

void            InitSnarks();
std::string     PRFapk      (const std::string& ask);
std::string     PRFConsentnf(const std::string& ask, const std::string& rho);
std::string     PRFIDnf     (const std::string& ask, const std::string& rho);
std::string     PRFStudynf  (const std::string& ask, const std::string& sid);
std::string     PRFHtag     (const std::string& ask, const std::string& hsig, size_t index);

}
#endif //__ZKC_PRF_H_