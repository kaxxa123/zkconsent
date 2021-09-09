// SPDX-License-Identifier: LGPL-3.0+

#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include "zkc_interface.hpp"
#include "clientdefs.hpp"

using namespace libzkconsent;
namespace po = boost::program_options;

void Heading()
{
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "zk Consent Proof Generator" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
}

CMDTYPS     GetCmd(std::string& sCmd)
{
    if (sCmd == "test") return CMD_TEST;
    if (sCmd == "setup") return CMD_SETUP;
    if (sCmd == "prove") return CMD_PROVE;
    if (sCmd == "verify") return CMD_VERIFY;
    return CMD_ERROR;
}

ZKCIRC      GetCircuit(bool bTerm, bool bMint, bool bConsent, bool bConfirm)
{
    int     iCnt    = 0;
    ZKCIRC  retCirc = ZK_ERROR;

    if (bTerm)  {
        retCirc = ZK_TERMINATE;
        ++iCnt;
    }

    if (bMint)  {
        retCirc = ZK_MINT;
        ++iCnt;
    }

    if (bConsent) {
        retCirc = ZK_CONSENT;
        ++iCnt;
    }

    if (bConfirm) {
        retCirc = ZK_CONFIRM;
        ++iCnt;
    }        

    return (iCnt == 1) ? retCirc : ZK_ERROR;
}

const char*    GetCircuitTag(ZKCIRC type)
{
    switch (type)
    {
        case ZK_TERMINATE:  
            return FILETAG_TERMINATE;
        case ZK_MINT:
            return FILETAG_MINT;
        case ZK_CONSENT:
            return FILETAG_CONSENT;
        case ZK_CONFIRM:
            return FILETAG_CONFIRM;
        default:
            break;
    }

    return "";
}

boost::filesystem::path GetBaseDir(ZKCIRC type)
{
    const char *path = std::getenv("HOME");
    if (path == nullptr)
        throw "FAILED: on getting home dir";

    return boost::filesystem::path(path) / "zkconsent_setup" / GetCircuitTag(type);
}

boost::filesystem::path GetDefPath(const char* szBaseFile, const char* szExt, ZKCIRC type)
{
    boost::filesystem::path     path = GetBaseDir(type);
    std::string                 filename = szBaseFile;

    filename += "_";
    filename += GetCircuitTag(type);
    filename += szExt;
    return path / filename;
}

int main(int argc, char** argv)
{
    // Options
    po::options_description options("");
    options.add_options()
        ("cmd", 
        po::value<std::string>(),
        "(REQUIRED) test | setup | prove | verify");

    options.add_options()
        ("zkterminate", "process user termination zkp");
    options.add_options()
        ("zkmint",      "process consent mint zkp");
    options.add_options()
        ("zkconsent",   "process consent change zkp");
    options.add_options()
        ("zkconfirm",   "process consent confirm zkp");

    options.add_options()
        ("witness,w",
        po::value<boost::filesystem::path>(),
        "(REQUIRED for prove) read witness from JSON file for proof generation.");

    options.add_options()
        ("keypair,k",
        po::value<boost::filesystem::path>(),
        "read/write keypair to BIN file. If it doesn't exist, a new "
        "keypair is generated under ~/zkconsent_setup");
    options.add_options()(
        "r1cs-json",
        po::value<boost::filesystem::path>(),
        "(setup) write r1cs to JSON file");
    options.add_options()(
        "pk-bin",
        po::value<boost::filesystem::path>(),
        "(setup) write proving key to BIN file");
    options.add_options()(
        "vk-bin",
        po::value<boost::filesystem::path>(),
        "(setup) write verification key to BIN file");
    options.add_options()(
        "vk-json",
        po::value<boost::filesystem::path>(),
        "(setup) write verification key to JSON file");

    options.add_options()(
        "extproof-json",
        po::value<boost::filesystem::path>(),
        "(prove) write extended proof to JSON file");
    options.add_options()(
        "proof-bin",
        po::value<boost::filesystem::path>(),
        "(prove | verify) read/write proof BIN file");
    options.add_options()(
        "primary-bin",
        po::value<boost::filesystem::path>(),
        "(prove | verify) read/write primary input BIN file");
    options.add_options()(
        "witness-bin",
        po::value<boost::filesystem::path>(),
        "(prove) write witness to BIN file (INSECURE!)");

    options.add_options()
        ("help,h", "show help");


    po::positional_options_description pos_desc;
        pos_desc.add("cmd", 1);

    Heading();
    auto usage = [&]() {
        std::cout << "Usage:"
                  << std::endl
                  << "  " << argv[0] << " cmd [<options>]" << std::endl
                  << std::endl;
        std::cout << options;
        std::cout << std::endl;
    };

    ZKCIRC      typeCirc = ZK_ERROR;
    CMDTYPS     typeCmd  = CMD_ERROR;

    std::string sCmd;
    boost::filesystem::path keypair_file;
    boost::filesystem::path r1cs_json_file;
    boost::filesystem::path pk_bin_file;
    boost::filesystem::path vk_bin_file;
    boost::filesystem::path vk_json_file;
    boost::filesystem::path witness_json_file;
    boost::filesystem::path exproof_json_file;
    boost::filesystem::path proof_bin_file;
    boost::filesystem::path primary_bin_file;
    boost::filesystem::path witness_bin_file;

    try {
        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).options(options).positional(pos_desc).run(), vm);
        po::notify(vm);

        if (vm.count("help")) {
            usage();
            return 1;
        }

        if (vm.count("cmd") != 1)
        {
            std::cout << " ERROR: Command required"  << std::endl;
            return 1;
        }

        sCmd    = vm["cmd"].as<std::string>();
        typeCmd = GetCmd(sCmd);
        if (typeCmd == CMD_ERROR)
        {
            std::cout << " ERROR: Unknown command: "  << sCmd << std::endl;
            return 1;
        }

        if (typeCmd != CMD_TEST)
        {
            typeCirc = GetCircuit(vm.count("zkterminate"), vm.count("zkmint"), vm.count("zkconsent"), vm.count("zkconfirm"));
            if (typeCirc == ZK_ERROR)
            {
                std::cout << " ERROR: Specify ONE of the circuit selection flags"  << std::endl;
                std::cout << "  zkterminate | zkmint | zkconsent | zkconfirm"  << std::endl;
                return 1;
            }
        }

        if (vm.count("keypair"))
            keypair_file = vm["keypair"].as<boost::filesystem::path>();

        if (vm.count("r1cs-json"))
            r1cs_json_file = vm["r1cs-json"].as<boost::filesystem::path>();

        if (vm.count("pk-bin"))
            pk_bin_file = vm["pk-bin"].as<boost::filesystem::path>();

        if (vm.count("vk-bin"))
            vk_bin_file = vm["vk-bin"].as<boost::filesystem::path>();

        if (vm.count("vk-json"))
            vk_json_file = vm["vk-json"].as<boost::filesystem::path>();

        if (vm.count("witness"))
            witness_json_file = vm["witness"].as<boost::filesystem::path>();

        if (vm.count("extproof-json"))
            exproof_json_file = vm["extproof-json"].as<boost::filesystem::path>();

        if (vm.count("proof-bin"))
            proof_bin_file = vm["proof-bin"].as<boost::filesystem::path>();

        if (vm.count("primary-bin"))
            primary_bin_file = vm["primary-bin"].as<boost::filesystem::path>();

        if (vm.count("witness-bin"))
            witness_bin_file = vm["witness-bin"].as<boost::filesystem::path>();

    } catch (po::error &error) {
        std::cerr << " ERROR: " << error.what() << std::endl;
        usage();
        return 1;
    }

    InitSnarks();

    boost::filesystem::path setup_dir = GetBaseDir(typeCirc);
    boost::filesystem::create_directories(setup_dir);
    
    switch(typeCmd)
    {
        case CMD_TEST: 
            TestAll(); 
            break;

        case CMD_SETUP: 
            if (keypair_file.empty())
                keypair_file = GetDefPath(BASE_KEYPAIR_FILE, BIN_EXT, typeCirc);

            if (r1cs_json_file.empty())
                r1cs_json_file = GetDefPath(BASE_R1CS_FILE, JSON_EXT, typeCirc);

            if (pk_bin_file.empty())
                pk_bin_file = GetDefPath(BASE_PK_FILE, BIN_EXT, typeCirc);

            if (vk_bin_file.empty())
                vk_bin_file = GetDefPath(BASE_VK_FILE, BIN_EXT, typeCirc);

            if (vk_json_file.empty())
                vk_json_file = GetDefPath(BASE_VK_FILE, JSON_EXT, typeCirc);

            TrustedSetup(typeCirc, keypair_file, pk_bin_file, vk_bin_file, vk_json_file, r1cs_json_file); 
            break;

        case CMD_PROVE:
            if (witness_json_file.empty())
            {
                std::cout << "Input witness required. Specify witness parameter." << std::endl;
                return 1;
            }
            
            if (keypair_file.empty())
                keypair_file = GetDefPath(BASE_KEYPAIR_FILE, BIN_EXT, typeCirc);

            if (exproof_json_file.empty())
                exproof_json_file = GetDefPath(BASE_EXPROOF_FILE, JSON_EXT, typeCirc);

            if (proof_bin_file.empty())
                proof_bin_file = GetDefPath(BASE_PROOF_FILE, BIN_EXT, typeCirc);

            if (primary_bin_file.empty())
                primary_bin_file = GetDefPath(BASE_PRIMARY_FILE, BIN_EXT, typeCirc);

            if (witness_bin_file.empty())
                witness_bin_file = GetDefPath(BASE_WITNESS_FILE, BIN_EXT, typeCirc);

            GenerateProof(  typeCirc, 
                            keypair_file, 
                            witness_json_file, 
                            exproof_json_file, 
                            proof_bin_file, 
                            primary_bin_file, 
                            witness_bin_file);
            break;

        case CMD_VERIFY:
            if (keypair_file.empty())
                keypair_file = GetDefPath(BASE_KEYPAIR_FILE, BIN_EXT, typeCirc);

            if (proof_bin_file.empty())
                proof_bin_file = GetDefPath(BASE_PROOF_FILE, BIN_EXT, typeCirc);

            if (primary_bin_file.empty())
                primary_bin_file = GetDefPath(BASE_PRIMARY_FILE, BIN_EXT, typeCirc);

            VerifyProof(typeCirc, 
                        keypair_file, 
                        proof_bin_file, 
                        primary_bin_file);
            break;

        default:
            std::cout << "UNEXPECTED: Unknown command" << std::endl;
    }

    return 0;
}
