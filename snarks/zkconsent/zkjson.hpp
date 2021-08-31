#ifndef __ZKJSON_HPP_
#define __ZKJSON_HPP_

using namespace libzkconsent;
using zkterminateT  = zkterminate_wrap<ppT, FieldT, HashT, HashTreeT, SnarkT, ZKC_TreeDepth>;        
using zkmintT       = zkmint_wrap<ppT, FieldT, HashT, HashTreeT, SnarkT, ZKC_TreeDepth>;        
using zkconsentT    = zkconsent_wrap<ppT, FieldT, HashT, HashTreeT, SnarkT, ZKC_TreeDepth>;        
using zkconfirmT    = zkconfirm_wrap<ppT, FieldT, HashT, HashTreeT, SnarkT, ZKC_TreeDepth>;        

template<class jsonT>
jsonT&  LoadZKJson(jsonT& zkjson, const boost::filesystem::path& jsonfile);

class zkterminate_json {
public:
using   circuitT = zkterminateT;

    zkterminate_json() {}
    zkterminate_json(const boost::filesystem::path& jsonfile) { set(jsonfile);  }
    zkterminate_json(const boost::json::object& objJSON) { set(objJSON);  }

    zkterminate_json& set(const boost::filesystem::path& jsonfile) {
        return LoadZKJson(*this, jsonfile);
    }
    zkterminate_json& set(const boost::json::object& objJSON);

    libzeth::extended_proof<ppT, SnarkT>    prove_test(circuitT& aZkp, const typename SnarkT::proving_key &proving_key) const;

    void trace();
private:
    std::string   a_sk;
    size_t        mkaddrId;
    std::string   rho;
    std::string   hsig;
};

class zkmint_json {
public:
using   circuitT = zkmintT;

    zkmint_json() {}
    zkmint_json(const boost::filesystem::path& jsonfile) { set(jsonfile);  }
    zkmint_json(const boost::json::object& objJSON) { set(objJSON);  }

    zkmint_json& set(const boost::filesystem::path& jsonfile) {
        return LoadZKJson(*this, jsonfile);
    }
    zkmint_json& set(const boost::json::object& objJSON);

    libzeth::extended_proof<ppT, SnarkT>    prove_test(circuitT& aZkp, const typename SnarkT::proving_key &proving_key) const;

    void trace();
private:
        std::string     a_sk;
        size_t          mkaddrStudy;
        std::string     studyid;
        size_t          mkaddrId;
        std::string     rhoId_in;
        std::string     rhoId_out;
        std::string     rhoConsent_out;
        std::string     traprConsent_out;
        bool            choice_out;
        std::string     hsig;
};

class zkconsent_json {
public:
using   circuitT = zkconsentT;

    zkconsent_json() {}
    zkconsent_json(const boost::filesystem::path& jsonfile) { set(jsonfile);  }
    zkconsent_json(const boost::json::object& objJSON) { set(objJSON);  }

    zkconsent_json& set(const boost::filesystem::path& jsonfile) {
        return LoadZKJson(*this, jsonfile);
    }
    zkconsent_json& set(const boost::json::object& objJSON);

    libzeth::extended_proof<ppT, SnarkT>    prove_test(circuitT& aZkp, const typename SnarkT::proving_key &proving_key) const;

    void trace();
private:
        std::string     a_sk;
        size_t          mkaddrStudy; 
        std::string     studyid;
        size_t          mkaddrId; 
        std::string     rhoId_in;
        std::string     rhoId_out;
        size_t          mkaddrConsent; 
        std::string     rhoConsent_in;
        std::string     traprConsent_in;
        bool            choice_in;
        std::string     rhoConsent_out;
        std::string     traprConsent_out;
        std::string     hsig;
};

class zkconfirm_json {
public:
using   circuitT = zkconfirmT;

    zkconfirm_json() {}
    zkconfirm_json(const boost::filesystem::path& jsonfile) { set(jsonfile);  }
    zkconfirm_json(const boost::json::object& objJSON) { set(objJSON);  }

    zkconfirm_json& set(const boost::filesystem::path& jsonfile) {
        return LoadZKJson(*this, jsonfile);
    }
    zkconfirm_json& set(const boost::json::object& objJSON);

    libzeth::extended_proof<ppT, SnarkT>    prove_test(circuitT& aZkp, const typename SnarkT::proving_key &proving_key) const;

    void trace();

private:
    std::string a_pk;
    std::string studyid;
    std::string rho;
    std::string trapr;
    bool choice;
};

template<class jsonT>
void    extract(boost::json::object const& objJson, jsonT& typ, boost::json::string_view key)
{
    typ = boost::json::value_to<jsonT>(objJson.at(key));
}

template<class jsonT>
jsonT&  LoadZKJson(jsonT& zkjson, const boost::filesystem::path& jsonfile)
{
    std::ifstream strm(jsonfile.c_str(), std::ifstream::in);
    boost::json::stream_parser jparser;

    if (strm.is_open()) {
        std::string sline;
        while (std::getline(strm,sline))
            jparser.write_some(sline.c_str());

        jparser.finish();
        strm.close();
    }

    boost::json::value jsonValue = jparser.release();
    boost::json::object const& obj = jsonValue.as_object();
    zkjson.set(obj);

    return zkjson;
}

#endif // __ZKJSON_HPP_
