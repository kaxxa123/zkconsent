#include <stdlib.h>
#include <iostream>
#include <memory>
#include <vector>
#include <algorithm>
#include <zkc_mktree.hpp>
#include <zkc_interface.hpp>

using namespace libzkconsent;

void TestPRFs()
{
    const char* ask  = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    const char* rho  = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    const char* hsig = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    std::string apk_expected = "2390c9e5370be7355f220b29caf3912ef970d828b73976ae9bfeb1402ce4c1f9";
    std::string nf_expected  = "ea43866d185e1bdb84713b699a2966d929d1392488c010c603e46a4cb92986f8";
    std::string htag0_expect = "8527fb92081cf832659a188163287f98b8c919401ba619d6ebd30dc0f1aedeff";
    std::string htag1_expect = "aea510673ff50225bec4bd918c102ea0c9b117b93534644ee70b74522b204b29";

    std::string apk = PRFapk(ask);
    std::string nf  = PRFConsentnf(ask,rho);
    std::string htag0 = PRFHtag(ask,hsig,0);
    std::string htag1 = PRFHtag(ask,hsig,1);

    std::cout << std::endl;
    std::cout << "=== Testing computation of a_pk from a_sk ===" << std::endl;
    std::cout << "a_sk:     " << ask << std::endl;
    std::cout << "a_pk:     " << apk << std::endl;

    std::transform(apk.begin(), apk.end(), apk.begin(), ::toupper);
    std::transform(apk_expected.begin(), apk_expected.end(), apk_expected.begin(), ::toupper);

    bool bVerified = (apk.compare(apk_expected) == 0);
    std::cout << "Verified: " << bVerified << std::endl << std::endl;
    if (!bVerified) throw "Unexpected: verification failed";


    std::cout << "=== Testing computation of consent nullifier ===" << std::endl;
    std::cout << "a_sk:     " << ask << std::endl;
    std::cout << "rho:      " << rho << std::endl;
    std::cout << "nf:       " << nf << std::endl;

    std::transform(nf.begin(), nf.end(), nf.begin(), ::toupper);
    std::transform(nf_expected.begin(), nf_expected.end(), nf_expected.begin(), ::toupper);

    bVerified = (nf.compare(nf_expected) == 0);
    std::cout << "Verified: " << bVerified << std::endl << std::endl;
    if (!bVerified) throw "Unexpected: verification failed";


    std::cout << "=== Testing computation of HTAGs ===" << std::endl;
    std::cout << "a_sk:     " << ask << std::endl;
    std::cout << "hsig:     " << hsig << std::endl;
    std::cout << "htag0:    " << htag0 << std::endl;
    std::cout << "htag1:    " << htag1 << std::endl;

    std::transform(htag0.begin(), htag0.end(), htag0.begin(), ::toupper);
    std::transform(htag0_expect.begin(), htag0_expect.end(), htag0_expect.begin(), ::toupper);

    bVerified = (htag0.compare(htag0_expect) == 0);
    std::cout << "Verifie0: " << bVerified << std::endl;
    if (!bVerified) throw "Unexpected: verification failed";

    std::transform(htag1.begin(), htag1.end(), htag1.begin(), ::toupper);
    std::transform(htag1_expect.begin(), htag1_expect.end(), htag1_expect.begin(), ::toupper);

    bVerified = (htag1.compare(htag1_expect) == 0);
    std::cout << "Verifie1: " << bVerified << std::endl << std::endl;
    if (!bVerified) throw "Unexpected: verification failed";
}

void TestMKTree() 
{
    std::string     cm_field = "104233707326581956155878965211552591892620143524616864409706009242461667751082";
    zkc_mktree      mktree;

    std::string  mkroot0 = mktree.get_root();
    mktree.set_value(1, cm_field);
    std::string  mkroot = mktree.get_root();
    std::string  mkleaf = mktree.get_value(1);

    std::cout << std::endl;
    std::cout << "=== Testing computation of MKTree values ===" << std::endl;
    std::cout << "Root0:    " << mkroot0 << std::endl;
    std::cout << "Root:     " << mkroot << std::endl;
    std::cout << "Leaf:     " << mkleaf << std::endl << std::endl;
}

void TestCMs()
{
    std::string a_pk    = "f172d7299ac8ac974ea59413e4a87691826df038ba24a2b52d5c5d15c2cc8c49";
    std::string rho     = "FFFF000000000000000000000000000000000000000000000000000000009009";
    std::string trap_r  = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    std::string studyid = "2F0000000000000F";

    std::string cmid_expected = FieldBound("61664778562247255656556823324184647250836269861294200639716623376346843163443");
                        // 61664778562247255656556823324184647250836269861294200639716623376346843163443
                        // % p 
                        // % 21888242871839275222246405745257275088696311157297823662689037894645226208583
                        // = 17888292818568705212064011833670097073739541060462131952320215003195226172209
    std::string cmid   = CMMid(a_pk, rho);

    std::cout << std::endl;
    std::cout << "=== Testing computation of Id Token Commitments ===" << std::endl;
    std::cout << "a_pk:     " << a_pk << std::endl;
    std::cout << "rho:      " << rho << std::endl;
    std::cout << "cmid:     " << cmid << std::endl;

    bool bVerified = (cmid.compare(cmid_expected) == 0);
    std::cout << "Verified: " << bVerified << std::endl << std::endl;
    if (!bVerified) throw "Unexpected: verification failed";


    std::string cmconsentOFF_expected = FieldBound("65214601563334233001744283039186002388797534047872762932441308784802186171368");
    std::string cmconsentON_expected  = FieldBound("102050420437744923720576593890046050762017115676399819899053203733659731501135");
    std::string cmconsentOFF  = CMMconsent(a_pk, rho, trap_r, studyid, false);
    std::string cmconsentON   = CMMconsent(a_pk, rho, trap_r, studyid, true);

    std::cout << "=== Testing computation of Consent Token Commitments ===" << std::endl;
    std::cout << "a_pk:     " << a_pk << std::endl;
    std::cout << "rho:      " << rho << std::endl;
    std::cout << "trap_r:   " << trap_r << std::endl;
    std::cout << "studyid:  " << studyid << std::endl  << std::endl;

    std::cout << "cmOFF:    " << cmconsentOFF << std::endl;
    bVerified = (cmconsentOFF.compare(cmconsentOFF_expected) == 0);
    std::cout << "Verified: " << bVerified << std::endl << std::endl;
    if (!bVerified) throw "Unexpected: verification failed";

    std::cout << "cmON:     " << cmconsentON << std::endl;
    bVerified = (cmconsentON.compare(cmconsentON_expected) == 0);
    std::cout << "Verified: " << bVerified << std::endl << std::endl;
    if (!bVerified) throw "Unexpected: verification failed";
}

void TestNoteId()
{
    const char* ask     = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    const char* rho     = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    size_t      mkAddr  = 1;

    std::string nf_expected  = PRFIDnf(ask, rho);
    std::string nf           = Test_NoteId_Input(ask, rho, mkAddr);

    std::transform(nf.begin(), nf.end(), nf.begin(), ::toupper);
    std::transform(nf_expected.begin(), nf_expected.end(), nf_expected.begin(), ::toupper);

    std::cout << std::endl;
    std::cout << "=== Testing computation of Note Id Input ===" << std::endl;
    std::cout << "a_sk:     " << ask << std::endl;
    std::cout << "rho:      " << rho << std::endl;
    std::cout << "nf:       " << nf << std::endl;

    bool bVerified = (nf.compare(nf_expected) == 0);
    std::cout << "Verified: " << bVerified << std::endl << std::endl;
    if (!bVerified) throw "Unexpected: verification failed";


    const char* a_pk    = "f172d7299ac8ac974ea59413e4a87691826df038ba24a2b52d5c5d15c2cc8c49";
    const char* rho2    = "FFFF000000000000000000000000000000000000000000000000000000009009";
    std::string cmid_expected = FieldBound("61664778562247255656556823324184647250836269861294200639716623376346843163443");
    std::string cmid    = Test_NoteId_Output(a_pk, rho2);

    std::cout << "=== Testing computation of Note Id Output ===" << std::endl;
    std::cout << "a_pk:     " << a_pk << std::endl;
    std::cout << "rho:      " << rho2 << std::endl;
    std::cout << "cmid:     " << cmid << std::endl;

    bVerified = (cmid.compare(cmid_expected) == 0);
    std::cout << "Verified: " << bVerified << std::endl << std::endl;
    if (!bVerified) throw "Unexpected: verification failed";
}

void TestNodeConsent() 
{
    std::string ask      = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    std::string rho0     = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    std::string trap_r0  = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    std::string studyid0 = "2F0000000000000F";
    bool        choice   = true;
    size_t      mkAddr  = 1;

    std::string nf_expected  = "ea43866d185e1bdb84713b699a2966d929d1392488c010c603e46a4cb92986f8";
    std::string nf           = Test_NoteConsent_Input(ask, rho0, trap_r0, studyid0, choice, mkAddr);

    std::transform(nf.begin(), nf.end(), nf.begin(), ::toupper);
    std::transform(nf_expected.begin(), nf_expected.end(), nf_expected.begin(), ::toupper);

    std::cout << std::endl;
    std::cout << "=== Testing computation of Note Consent Input ===" << std::endl;
    std::cout << "a_sk:     " << ask << std::endl;
    std::cout << "rho:      " << rho0 << std::endl;
    std::cout << "trap_r:   " << trap_r0 << std::endl;
    std::cout << "studyid:  " << studyid0 << std::endl;
    std::cout << "choice:   " << choice << std::endl;
    std::cout << "nf:       " << nf << std::endl;

    bool bVerified = (nf.compare(nf_expected) == 0);
    std::cout << "Verified: " << bVerified << std::endl << std::endl;
    if (!bVerified) throw "Unexpected: verification failed";


    std::string a_pk    = "f172d7299ac8ac974ea59413e4a87691826df038ba24a2b52d5c5d15c2cc8c49";
    std::string rho     = "FFFF000000000000000000000000000000000000000000000000000000009009";
    std::string trap_r  = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    std::string studyid = "2F0000000000000F";

    std::string cmconsentOFF_expected = FieldBound("65214601563334233001744283039186002388797534047872762932441308784802186171368");
    std::string cmconsentON_expected  = FieldBound("102050420437744923720576593890046050762017115676399819899053203733659731501135");

    std::string cmconsentOFF   = Test_NoteConsent_Output(a_pk, rho, trap_r, studyid, false);
    std::string cmconsentON    = Test_NoteConsent_Output(a_pk, rho, trap_r, studyid, true);

    std::cout << std::endl;
    std::cout << "=== Testing computation of Note Consent Output ===" << std::endl;
    std::cout << "a_pk:     " << a_pk << std::endl;
    std::cout << "rho:      " << rho << std::endl;
    std::cout << "trap_r:   " << trap_r << std::endl;
    std::cout << "studyid:  " << studyid << std::endl  << std::endl;

    std::cout << "cmOFF:    " << cmconsentOFF << std::endl;
    bVerified = (cmconsentOFF.compare(cmconsentOFF_expected) == 0);
    std::cout << "Verified: " << bVerified << std::endl << std::endl;
    if (!bVerified) throw "Unexpected: verification failed";

    std::cout << "cmON:     " << cmconsentON << std::endl;
    bVerified = (cmconsentON.compare(cmconsentON_expected) == 0);
    std::cout << "Verified: " << bVerified << std::endl << std::endl;
    if (!bVerified) throw "Unexpected: verification failed";
}

void TestStudy()
{
    const char* ask       = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    std::string studyid   = "2F0000000000000F";
    size_t      mkAddr    = 1;

    std::string nf_expected  = PRFStudynf(ask, studyid);
    std::string nf           = Test_Study_Input(ask, studyid, mkAddr);

    std::transform(nf.begin(), nf.end(), nf.begin(), ::toupper);
    std::transform(nf_expected.begin(), nf_expected.end(), nf_expected.begin(), ::toupper);

    std::cout << std::endl;
    std::cout << "=== Testing computation of Study Input ===" << std::endl;
    std::cout << "a_sk:     " << ask << std::endl;
    std::cout << "studyid:  " << studyid << std::endl;
    std::cout << "nf:       " << nf << std::endl;

    bool bVerified = (nf.compare(nf_expected) == 0);
    std::cout << "Verified: " << bVerified << std::endl << std::endl;
    if (!bVerified) throw "Unexpected: verification failed";
}

void TestTerminate()
{
    std::string ask     = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    std::string rho     = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    std::string hsig    = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    size_t      mkAddr  = 1;

    std::cout << std::endl;
    std::cout << "=== Testing computation of Termination proof witness ===" << std::endl;

    bool bVerified = Test_UserTerminate(ask, mkAddr, rho, hsig);
    std::cout << "Verified: " << bVerified << std::endl << std::endl;
    if (!bVerified) throw "Unexpected: verification failed";
}

void TestMint()
{
    std::string ask                 = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";

    size_t      mkaddrStudy         = 23;
    std::string studyid             = "2F0000000000000F";

    size_t      mkaddrId            = 1;
    std::string rhoId_in            = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    std::string rhoId_out           = "1F000000000000FF00000000000000FF00000000000000FF00000000000000FF";

    std::string rhoConsent_out      = "4F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    std::string traprConsent_out    = "5F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    bool        choice              = false;

    std::string hsig                = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";

    std::cout << std::endl;
    std::cout << "=== Testing computation of Minting proof witness ===" << std::endl;


    bool bVerified = Test_ConsentMint(ask,
                        mkaddrStudy, studyid,
                        mkaddrId, rhoId_in, rhoId_out,
                        rhoConsent_out, traprConsent_out, choice,
                        hsig);

    std::cout << "Verified: " << bVerified << std::endl << std::endl;
    if (!bVerified) throw "Unexpected: verification failed";
}

void TestChgConsent()
{
    std::string ask                 = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";

    size_t      mkaddrStudy         = 23;
    std::string studyid             = "2F0000000000000F";

    size_t      mkaddrId            = 1;
    std::string rhoId_in            = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    std::string rhoId_out           = "1F000000000000FF00000000000000FF00000000000000FF00000000000000FF";

    size_t      mkaddrConsent       = 4;
    std::string rhoConsent_in      = "2F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    std::string traprConsent_in    = "3F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    bool        choice              = true;

    std::string rhoConsent_out      = "4F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    std::string traprConsent_out    = "5F000000000000FF00000000000000FF00000000000000FF00000000000000FF";

    std::string hsig                = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";

    std::cout << std::endl;
    std::cout << "=== Testing computation of Consent Change proof witness ===" << std::endl;

    bool bVerified = Test_ConsentChg(ask,
                        mkaddrStudy, studyid,
                        mkaddrId, rhoId_in, rhoId_out,
                        mkaddrConsent, rhoConsent_in, traprConsent_in, choice,
                        rhoConsent_out, traprConsent_out,
                        hsig);
    
    std::cout << "Verified: " << bVerified << std::endl << std::endl;
    if (!bVerified) throw "Unexpected: verification failed";
}

int main()
{
    InitSnarks();
    TestPRFs();
    TestMKTree();
    TestCMs();
    TestNoteId();
    TestNodeConsent();
    TestStudy();
    TestTerminate();
    TestMint();
    TestChgConsent();
    return 0;
}
