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

std::string      Test_NoteConsent_Input(
                    const std::string&  s_ask, 
                    const std::string&  s_rho,
                    const std::string&  s_trap_r,
                    const std::string&  s_studyid,
                    bool                choice,
                    size_t              mkAddr);

std::string      Test_NoteConsent_Output(
                    const std::string&  s_apk, 
                    const std::string&  s_rho,
                    const std::string&  s_trap_r,
                    const std::string&  s_studyid,
                    bool                choice);

std::string      Test_Study_Input(
                    const std::string&  s_ask, 
                    const std::string&  s_studyid,
                    size_t              mkAddr);

bool            Test_UserTerminate(
                    const std::string&  s_ask,
                    size_t              mkAddr, 
                    const std::string&  s_rho,
                    const std::string&  s_hsig);
                    
bool            Test_ConsentMint(
                    const std::string&  s_ask,
                    size_t              mkaddrStudy, 
                    const std::string&  s_studyid,
                    size_t              mkaddrId, 
                    const std::string&  s_rhoId_in,
                    const std::string&  s_rhoId_out,
                    const std::string&  s_rhoConsent_out,
                    const std::string&  s_traprConsent_out,
                    bool                choice_out,
                    const std::string&  s_hsig);

bool            Test_ConsentChg(
                    const std::string&  s_ask,
                    size_t              mkaddrStudy, 
                    const std::string&  s_studyid,
                    size_t              mkaddrId, 
                    const std::string&  s_rhoId_in,
                    const std::string&  s_rhoId_out,
                    size_t              mkaddrConsent, 
                    const std::string&  s_rhoConsent_in,
                    const std::string&  s_traprConsent_in,
                    bool                choice_in,
                    const std::string&  s_rhoConsent_out,
                    const std::string&  s_traprConsent_out,
                    const std::string&  s_hsig);
}
#endif //__ZKC_INTERFACE_H_