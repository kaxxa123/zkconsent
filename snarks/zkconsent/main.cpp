#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
//#include <boost/json/src.hpp>
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

boost::filesystem::path GetBaseDir()
{
    const char *path = std::getenv("HOME");
    if (path == nullptr)
        throw "FAILED: on getting home dir";

    return boost::filesystem::path(path) /  "zkconsent_setup";
}

boost::filesystem::path GetDefPath(const char* szBaseFile, const char* szExt, ZKCIRC type)
{
    boost::filesystem::path     path = GetBaseDir();
    std::string                 filename = szBaseFile;

    switch (type)
    {
        case ZK_TERMINATE:  
            filename += "_" FILETAG_TERMINATE;
            break;
        case ZK_MINT:
            filename += "_" FILETAG_MINT;
            break;
        case ZK_CONSENT:
            filename += "_" FILETAG_CONSENT;
            break;
        case ZK_CONFIRM:
            filename += "_" FILETAG_CONFIRM;
            break;
        default:
            break;
    }
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
        "test | setup | prove");
    options.add_options()
        ("help,h", "show help");

    options.add_options()
        ("keypair,k",
        po::value<boost::filesystem::path>(),
        "file to load keypair from. If it doesn't exist, a new keypair will be "
        "generated and written to this file. (default: "
        "~/zkconsent_setup/keypair_<circuit>.bin)");
    options.add_options()(
        "r1cs,r",
        po::value<boost::filesystem::path>(),
        "file in which to export the r1cs (in json format)");
    options.add_options()(
        "proving-key-output",
        po::value<boost::filesystem::path>(),
        "write proving key to file (if generated)");
    options.add_options()(
        "verification-key-output",
        po::value<boost::filesystem::path>(),
        "write verification key to file (if generated)");

    options.add_options()
        ("zkterminate", "process user termination zkp");
    options.add_options()
        ("zkmint",      "process consent mint zkp");
    options.add_options()
        ("zkconsent",   "process consent change zkp");
    options.add_options()
        ("zkconfirm",   "process consent confirm zkp");

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
    boost::filesystem::path pk_output_file;
    boost::filesystem::path vk_output_file;

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

        if (vm.count("proving-key-output"))
            pk_output_file = vm["proving-key-output"].as<boost::filesystem::path>();

        if (vm.count("verification-key-output"))
            vk_output_file = vm["verification-key-output"].as<boost::filesystem::path>();

    } catch (po::error &error) {
        std::cerr << " ERROR: " << error.what() << std::endl;
        usage();
        return 1;
    }

    InitSnarks();

    boost::filesystem::path setup_dir = GetBaseDir();
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

            if (pk_output_file.empty())
                pk_output_file = GetDefPath(BASE_PK_FILE, BIN_EXT, typeCirc);

            if (vk_output_file.empty())
                vk_output_file = GetDefPath(BASE_VK_FILE, BIN_EXT, typeCirc);

            TrustedSetup(typeCirc, keypair_file, pk_output_file, vk_output_file, r1cs_file); 
            break;

        case CMD_PROVE:
            if (keypair_file.empty())
                keypair_file = GetDefPath(BASE_KEYPAIR_FILE, BIN_EXT, typeCirc);

            GenerateProve(typeCirc, keypair_file);
            break;

        default:
            std::cout << "UNEXPECTED: Unknown command" << std::endl;
    }

    return 0;
}
