#ifndef __PRFXXX_H_
#define __PRFXXX_H_

std::string     digest2hex(const std::vector<bool>& digest);
std::string     PRFapk(const char* szAsk);
std::string     PRFnf (const char* szAsk, const char* szRho);

#endif //__PRFXXX_H_