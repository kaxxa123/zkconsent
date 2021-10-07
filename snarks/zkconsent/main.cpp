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

boost::filesystem::path GetBaseDir(bool bGroth16, ZKCIRC type)
{
    const char *scheme = bGroth16 ? SCHEMEFLD_GROTH16 : SCHEMEFLD_PGHR13;
    const char *path   = std::getenv("HOME");
    if (path == nullptr)
        throw "FAILED: on getting home dir";

    return boost::filesystem::path(path) / "zkconsent_setup" / scheme / GetCircuitTag(type);
}

boost::filesystem::path GetDefPath(bool bGroth16, const char* szBaseFile, const char* szExt, ZKCIRC type)
{
    boost::filesystem::path     path = GetBaseDir(bGroth16, type);
    std::string                 filename = szBaseFile;

    filename += "_";
    filename += GetCircuitTag(type);
    filename += szExt;
    return path / filename;
}

void CreatePath(boost::filesystem::path& path)
{
    boost::filesystem::path temp = path;

    if (temp.has_filename())
            boost::filesystem::create_directories(temp.remove_filename());
    else    boost::filesystem::create_directories(temp);
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
        ("groth16", "Run with Groth16 ZKP Scheme (default)");
    options.add_options()
        ("pghr13",  "Run with PGHR13 ZKP Scheme");

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
    bool        bGroth16 = true;

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
            std::cerr << " ERROR: Command required"  << std::endl;
            return 1;
        }

        sCmd    = vm["cmd"].as<std::string>();
        typeCmd = GetCmd(sCmd);
        if (typeCmd == CMD_ERROR)
        {
            std::cerr << " ERROR: Unknown command: "  << sCmd << std::endl;
            return 1;
        }

        if (typeCmd != CMD_TEST)
        {
            typeCirc = GetCircuit(vm.count("zkterminate"), vm.count("zkmint"), vm.count("zkconsent"), vm.count("zkconfirm"));
            if (typeCirc == ZK_ERROR)
            {
                std::cerr << " ERROR: Specify ONE of the circuit selection flags"  << std::endl;
                std::cerr << "  zkterminate | zkmint | zkconsent | zkconfirm"  << std::endl;
                return 1;
            }
        }

        if (vm.count("groth16") && vm.count("pghr13"))
        {
            std::cerr << " ERROR: Specify only ONE ZKP Scheme from"  << std::endl;
            std::cerr << "  groth16 | pghr13"  << std::endl;
            return 1;
        }
        bGroth16 = vm.count("groth16") || !vm.count("pghr13");

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

    switch(typeCmd)
    {
        case CMD_TEST: 
            TestAll(); 
            break;

        case CMD_SETUP: 
            if (keypair_file.empty())
                keypair_file = GetDefPath(bGroth16, BASE_KEYPAIR_FILE, BIN_EXT, typeCirc);

            if (r1cs_json_file.empty())
                r1cs_json_file = GetDefPath(bGroth16, BASE_R1CS_FILE, JSON_EXT, typeCirc);

            if (pk_bin_file.empty())
                pk_bin_file = GetDefPath(bGroth16, BASE_PK_FILE, BIN_EXT, typeCirc);

            if (vk_bin_file.empty())
                vk_bin_file = GetDefPath(bGroth16, BASE_VK_FILE, BIN_EXT, typeCirc);

            if (vk_json_file.empty())
                vk_json_file = GetDefPath(bGroth16, BASE_VK_FILE, JSON_EXT, typeCirc);

            if (!keypair_file.has_filename() || 
                !r1cs_json_file.has_filename() || 
                !pk_bin_file.has_filename() || 
                !vk_bin_file.has_filename() || 
                !vk_json_file.has_filename()) {
                std::cerr << " ERROR: " << "Invalid Input filename" << std::endl;
                return 1;
            }

            CreatePath(keypair_file);
            CreatePath(r1cs_json_file);
            CreatePath(pk_bin_file);
            CreatePath(vk_bin_file);
            CreatePath(vk_json_file);

            std::cout << " KeyPair BIN: " << keypair_file << std::endl;
            std::cout << " R1CS JSON:   " << r1cs_json_file << std::endl;
            std::cout << " PK BIN:      " << pk_bin_file << std::endl;
            std::cout << " VK BIN:      " << vk_bin_file << std::endl;
            std::cout << " VK JSON:     " << vk_json_file << std::endl;

            TrustedSetup(bGroth16, typeCirc, keypair_file, pk_bin_file, vk_bin_file, vk_json_file, r1cs_json_file); 
            break;

        case CMD_PROVE:
            if (witness_json_file.empty())
            {
                std::cerr << "Input witness required. Specify witness parameter." << std::endl;
                return 1;
            }
            
            if (keypair_file.empty())
                keypair_file = GetDefPath(bGroth16, BASE_KEYPAIR_FILE, BIN_EXT, typeCirc);

            if (exproof_json_file.empty())
                exproof_json_file = GetDefPath(bGroth16, BASE_EXPROOF_FILE, JSON_EXT, typeCirc);

            if (proof_bin_file.empty())
                proof_bin_file = GetDefPath(bGroth16, BASE_PROOF_FILE, BIN_EXT, typeCirc);

            if (primary_bin_file.empty())
                primary_bin_file = GetDefPath(bGroth16, BASE_PRIMARY_FILE, BIN_EXT, typeCirc);

            if (witness_bin_file.empty())
                witness_bin_file = GetDefPath(bGroth16, BASE_WITNESS_FILE, BIN_EXT, typeCirc);

            if (!witness_json_file.has_filename() || 
                !keypair_file.has_filename() || 
                !exproof_json_file.has_filename() || 
                !proof_bin_file.has_filename() || 
                !primary_bin_file.has_filename() || 
                !witness_bin_file.has_filename() ) {
                std::cerr << " ERROR: " << "Invalid Input filename" << std::endl;
                return 1;
            }

            CreatePath(witness_json_file);
            CreatePath(keypair_file);
            CreatePath(exproof_json_file);
            CreatePath(proof_bin_file);
            CreatePath(primary_bin_file);
            CreatePath(witness_bin_file);

            std::cout << " Witness Input: " << witness_json_file << std::endl;
            std::cout << " KeyPair BIN:   " << keypair_file << std::endl;
            std::cout << " ExProof JSON:  " << exproof_json_file << std::endl;
            std::cout << " Proof BIN:     " << proof_bin_file << std::endl;
            std::cout << " Primary BIN:   " << primary_bin_file << std::endl;
            std::cout << " Witness BIN:   " << witness_bin_file << std::endl;

            GenerateProof(  bGroth16,
                            typeCirc, 
                            keypair_file, 
                            witness_json_file, 
                            exproof_json_file, 
                            proof_bin_file, 
                            primary_bin_file, 
                            witness_bin_file);
            break;

        case CMD_VERIFY: 
            if (keypair_file.empty())
                keypair_file = GetDefPath(bGroth16, BASE_KEYPAIR_FILE, BIN_EXT, typeCirc);

            if (proof_bin_file.empty())
                proof_bin_file = GetDefPath(bGroth16, BASE_PROOF_FILE, BIN_EXT, typeCirc);

            if (primary_bin_file.empty())
                primary_bin_file = GetDefPath(bGroth16, BASE_PRIMARY_FILE, BIN_EXT, typeCirc);

            if (!keypair_file.has_filename() || 
                !proof_bin_file.has_filename() || 
                !primary_bin_file.has_filename()) {
                std::cerr << " ERROR: " << "Invalid Input filename" << std::endl;
                return 1;
            }

            CreatePath(keypair_file);
            CreatePath(proof_bin_file);
            CreatePath(primary_bin_file);

            std::cout << " KeyPair BIN: " << keypair_file << std::endl;
            std::cout << " Proof BIN:   " << proof_bin_file << std::endl;
            std::cout << " Primary BIN: " << primary_bin_file << std::endl;

            VerifyProof(bGroth16, 
                        typeCirc, 
                        keypair_file, 
                        proof_bin_file, 
                        primary_bin_file);
            break;

        default:
            std::cerr << "UNEXPECTED: Unknown command" << std::endl;
    }

    return 0;
}
