#ifndef __CLIENTDEFS_HPP_
#define __CLIENTDEFS_HPP_

#define FILETAG_MINT        "zkmint"
#define FILETAG_CONSENT     "zkcons"
#define FILETAG_CONFIRM     "zkconf"
#define FILETAG_TERMINATE   "zkterm"

#define BASE_KEYPAIR_FILE   "keypair"
#define BASE_PK_FILE        "pk"
#define BASE_VK_FILE        "vk"
#define BASE_R1CS_FILE      "r1cs"
#define BIN_EXT             ".bin"
#define JSON_EXT            ".json"

enum    ZKCIRC {
    ZK_TERMINATE,
    ZK_MINT,
    ZK_CONSENT,
    ZK_CONFIRM,
    ZK_ERROR
};

enum    CMDTYPS {
    CMD_TEST,
    CMD_PROVE,
    CMD_SETUP,
    CMD_ERROR
};

void TestAll();
void TrustedSetup(
    ZKCIRC type, 
    const boost::filesystem::path &keypair_file,
    const boost::filesystem::path &pk_file,
    const boost::filesystem::path &vk_file,
    const boost::filesystem::path &r1cs_file);

#endif // __CLIENTDEFS_HPP_
