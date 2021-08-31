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
        "(REQUIRED) test | setup | prove");

    options.add_options()
        ("zkterminate", "process user termination zkp");
    options.add_options()
        ("zkmint",      "process consent mint zkp");
    options.add_options()
        ("zkconsent",   "process consent change zkp");
    options.add_options()
        ("zkconfirm",   "process consent confirm zkp");

    options.add_options()
        ("proof-in,p",
        po::value<boost::filesystem::path>(),
        "(REQUIRED for prove) Input file containing the proof parameters.");

    options.add_options()
        ("keypair,k",
        po::value<boost::filesystem::path>(),
        "file to load keypair from. If it doesn't exist, a new "
        "keypair will be generated under ~/zkconsent_setup");
    options.add_options()(
        "r1cs",
        po::value<boost::filesystem::path>(),
        "(setup) write r1cs to JSON file");
    options.add_options()(
        "proving-key-out",
        po::value<boost::filesystem::path>(),
        "(setup) write proving key to file");
    options.add_options()(
        "verification-key-out",
        po::value<boost::filesystem::path>(),
        "(setup) write verification key to file");

    options.add_options()(
        "extproof-json-out",
        po::value<boost::filesystem::path>(),
        "(prove) write extended proof JSON to file");
    options.add_options()(
        "proof-out",
        po::value<boost::filesystem::path>(),
        "(prove) write raw proof to file");
    options.add_options()(
        "witness-out",
        po::value<boost::filesystem::path>(),
        "(prove) write witness to file (INSECURE!)");

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
    boost::filesystem::path r1cs_file;
    boost::filesystem::path pk_out_file;
    boost::filesystem::path vk_out_file;
    boost::filesystem::path proof_in_file;
    boost::filesystem::path exproof_out_file;
    boost::filesystem::path proof_out_file;
    boost::filesystem::path primary_out_file;
    boost::filesystem::path witness_out_file;

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

        if (vm.count("r1cs"))
            r1cs_file = vm["r1cs"].as<boost::filesystem::path>();

        if (vm.count("proving-key-out"))
            pk_out_file = vm["proving-key-out"].as<boost::filesystem::path>();

        if (vm.count("verification-key-out"))
            vk_out_file = vm["verification-key-out"].as<boost::filesystem::path>();

        if (vm.count("proof-in"))
            proof_in_file = vm["proof-in"].as<boost::filesystem::path>();

        if (vm.count("extproof-json-out"))
            exproof_out_file = vm["extproof-json-out"].as<boost::filesystem::path>();

        if (vm.count("proof-out"))
            proof_out_file = vm["proof-out"].as<boost::filesystem::path>();

        if (vm.count("primary-out"))
            primary_out_file = vm["primary-out"].as<boost::filesystem::path>();

        if (vm.count("witness-out"))
            witness_out_file = vm["witness-out"].as<boost::filesystem::path>();

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

            if (r1cs_file.empty())
                r1cs_file = GetDefPath(BASE_R1CS_FILE, JSON_EXT, typeCirc);

            if (pk_out_file.empty())
                pk_out_file = GetDefPath(BASE_PK_FILE, BIN_EXT, typeCirc);

            if (vk_out_file.empty())
                vk_out_file = GetDefPath(BASE_VK_FILE, BIN_EXT, typeCirc);

            TrustedSetup(typeCirc, keypair_file, pk_out_file, vk_out_file, r1cs_file); 
            break;

        case CMD_PROVE:
            if (proof_in_file.empty())
            {
                std::cout << "Input proof parameters required. Specify proof parameter." << std::endl;
                return 1;
            }
            
            if (keypair_file.empty())
                keypair_file = GetDefPath(BASE_KEYPAIR_FILE, BIN_EXT, typeCirc);

            if (exproof_out_file.empty())
                exproof_out_file = GetDefPath(BASE_EXPROOF_FILE, JSON_EXT, typeCirc);

            if (proof_out_file.empty())
                proof_out_file = GetDefPath(BASE_PROOF_FILE, BIN_EXT, typeCirc);

            if (primary_out_file.empty())
                primary_out_file = GetDefPath(BASE_PRIMARY_FILE, BIN_EXT, typeCirc);

            if (witness_out_file.empty())
                witness_out_file = GetDefPath(BASE_WITNESS_FILE, BIN_EXT, typeCirc);

            GenerateProve(  typeCirc, 
                            keypair_file, 
                            proof_in_file, 
                            exproof_out_file, 
                            proof_out_file, 
                            primary_out_file, 
                            witness_out_file);
            break;

        default:
            std::cout << "UNEXPECTED: Unknown command" << std::endl;
    }

    return 0;
}
