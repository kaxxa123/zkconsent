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
#define BASE_EXPROOF_FILE   "exproof"
#define BASE_PROOF_FILE     "proof"
#define BASE_PRIMARY_FILE   "primary"
#define BASE_WITNESS_FILE   "witness"
#define BIN_EXT             ".bin"
#define JSON_EXT            ".json"
#define TXT_EXT             ".txt"

enum    ZKCIRC {
    ZK_TERMINATE,
    ZK_MINT,
    ZK_CONSENT,
    ZK_CONFIRM,
    ZK_ERROR
};

enum    CMDTYPS {
    CMD_TEST,
    CMD_SETUP,
    CMD_PROVE,
    CMD_VERIFY,
    CMD_ERROR
};

void TestAll();

void TrustedSetup(
    ZKCIRC type, 
    const boost::filesystem::path &keypair_file,
    const boost::filesystem::path &pk_bin_file,
    const boost::filesystem::path &vk_bin_file,
    const boost::filesystem::path &vk_txt_file, 
    const boost::filesystem::path &r1cs_json_file);

void GenerateProof(
    ZKCIRC type, 
    const boost::filesystem::path &keypair_file,
    const boost::filesystem::path &witness_json_file,
    const boost::filesystem::path &exproof_json_file,
    const boost::filesystem::path &proof_bin_file,
    const boost::filesystem::path &primary_bin_file,
    const boost::filesystem::path &witness_bin_file);

void VerifyProof(
    ZKCIRC type, 
    const boost::filesystem::path &keypair_file,
    const boost::filesystem::path &proof_bin_file,
    const boost::filesystem::path &primary_bin_file);

#endif // __CLIENTDEFS_HPP_
