#ifndef __ZKC_INTERFACE_H_
#define __ZKC_INTERFACE_H_

namespace libzkconsent
{

void            InitSnarks();
std::string     FieldBound(const std::string& value);

std::string     PRFapk      (const std::string& ask);
std::string     PRFConsentnf(const std::string& ask, const std::string& rho);
std::string     PRFIDnf     (const std::string& ask, const std::string& rho);
std::string     PRFStudynf  (const std::string& ask, const std::string& sid);
std::string     PRFHtag     (const std::string& ask, const std::string& hsig, size_t index);

std::string     CMMid(const std::string& a_pk, const std::string& rho);
std::string     CMMconsent(
                    const std::string& sapk, 
                    const std::string& srho,
                    const std::string& sr,
                    const std::string& sid,
                    bool bChoice);

std::string      Test_NoteId_Input(
                    const std::string&  s_ask, 
                    const std::string&  s_rho,
                    size_t              mkAddr);

std::string      Test_NoteId_Output(
                    const std::string&  s_apk, 
                    const std::string&  s_rho);

std::string      Test_NoteConsent_Output(
                    const std::string&  s_apk, 
                    const std::string&  s_rho,
                    const std::string&  s_trap_r,
                    const std::string&  s_studyid,
                    bool                choice);
}
#endif //__ZKC_INTERFACE_H_