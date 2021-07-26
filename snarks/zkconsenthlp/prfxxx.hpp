#ifndef __PRFXXX_H_
#define __PRFXXX_H_

void            InitSnarks();
std::string     PRFapk      (const std::string& ask);
std::string     PRFConsentnf(const std::string& ask, const std::string& rho);
std::string     PRFIDnf     (const std::string& ask, const std::string& rho);
std::string     PRFStudynf  (const std::string& ask, const std::string& sid);

#endif //__PRFXXX_H_