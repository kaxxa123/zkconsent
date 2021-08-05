#include <stdlib.h>
#include <iostream>
#include <memory>
#include <vector>
#include <algorithm>
#include <zkc_mktree.hpp>
#include <zkc_prf.hpp>

void TestPRFs()
{
    const char* ask = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    const char* rho = "0F000000000000FF00000000000000FF00000000000000FF00000000000000FF";
    std::string apk_expected = "2390c9e5370be7355f220b29caf3912ef970d828b73976ae9bfeb1402ce4c1f9";
    std::string nf_expected  = "ea43866d185e1bdb84713b699a2966d929d1392488c010c603e46a4cb92986f8";

    std::string apk = PRFapk(ask);
    std::string nf  = PRFConsentnf(ask,rho);

    std::cout << "a_sk:     " << ask << std::endl;
    std::cout << "a_pk:     " << apk << std::endl;

    std::transform(apk.begin(), apk.end(), apk.begin(), ::toupper);
    std::transform(apk_expected.begin(), apk_expected.end(), apk_expected.begin(), ::toupper);
    std::cout << "Verifies: " << (apk.compare(apk_expected) == 0) << std::endl << std::endl;

    std::cout << "a_sk:     " << ask << std::endl;
    std::cout << "rho:      " << rho << std::endl;
    std::cout << "nf:       " << nf << std::endl;

    std::transform(nf.begin(), nf.end(), nf.begin(), ::toupper);
    std::transform(nf_expected.begin(), nf_expected.end(), nf_expected.begin(), ::toupper);
    std::cout << "Verifies: " << (nf.compare(nf_expected) == 0) << std::endl << std::endl;
}

void TestMKTree() 
{
    std::string     cm_field = "104233707326581956155878965211552591892620143524616864409706009242461667751082";
    zkc_mktree      mktree;

    std::string  mkroot0 = mktree.get_root();
    mktree.set_value(1, cm_field);
    std::string  mkroot = mktree.get_root();
    std::string  mkleaf = mktree.get_value(1);

    std::cout << "Root0: "<< mkroot0 << std::endl;
    std::cout << "Root:  "<< mkroot << std::endl;
    std::cout << "Leaf:  "<< mkleaf << std::endl;
}

int main()
{
    InitSnarks();
    TestPRFs();
    TestMKTree();

    return 0;
}
