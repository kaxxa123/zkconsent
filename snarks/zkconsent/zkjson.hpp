// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZKJSON_HPP_
#define __ZKJSON_HPP_

using namespace libzkconsent;

template<class jsonT>
jsonT&  LoadZKJson(jsonT& zkjson, const boost::filesystem::path& jsonfile);

template<typename snarkT>
class zkterminate_base_json {
public:
    zkterminate_base_json() {}
    zkterminate_base_json(const boost::filesystem::path& jsonfile) { set(jsonfile);  }
    zkterminate_base_json(const boost::json::object& objJSON) { set(objJSON);  }

    zkterminate_base_json<snarkT>& set(const boost::filesystem::path& jsonfile) {
        return LoadZKJson(*this, jsonfile);
    }
    zkterminate_base_json<snarkT>& set(const boost::json::object& objJSON);

    void trace();
protected:
    std::string   a_sk;
    size_t        mkaddrId;
    std::string   rhoId_in;
    std::string   rhoId_out;
    std::string   hsig;
};

template<typename snarkT>
class zkterminate_json : public zkterminate_base_json<snarkT> {
public:
using   circuitT = zkterminate_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, ZKC_TreeDepth>;
using   zkterminate_base_json<snarkT>::zkterminate_base_json;

    libzeth::extended_proof<ppT, snarkT>    prove_test(circuitT& aZkp, const typename snarkT::proving_key &proving_key) const;
};

template<typename snarkT>
class zkterminate_simp_json : public zkterminate_base_json<snarkT> {
public:
using   circuitT = zkterminate_simp_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, ZKC_TreeDepth>;
using   zkterminate_base_json<snarkT>::zkterminate_base_json;

    libzeth::extended_proof<ppT, snarkT>    prove_test(circuitT& aZkp, const typename snarkT::proving_key &proving_key) const;
};

template<typename snarkT>
class zkmint_base_json {
public:
    zkmint_base_json() {}
    zkmint_base_json(const boost::filesystem::path& jsonfile) { set(jsonfile);  }
    zkmint_base_json(const boost::json::object& objJSON) { set(objJSON);  }

    zkmint_base_json<snarkT>& set(const boost::filesystem::path& jsonfile) {
        return LoadZKJson(*this, jsonfile);
    }
    zkmint_base_json<snarkT>& set(const boost::json::object& objJSON);

    void trace();
protected:
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

template<typename snarkT>
class zkmint_json : public zkmint_base_json<snarkT> {
public:
using   circuitT = zkmint_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, ZKC_TreeDepth>;        
using   zkmint_base_json<snarkT>::zkmint_base_json;

    libzeth::extended_proof<ppT, snarkT>    prove_test(circuitT& aZkp, const typename snarkT::proving_key &proving_key) const;
};

template<typename snarkT>
class zkmint_simp_json : public zkmint_base_json<snarkT> {
public:
using   circuitT = zkmint_simp_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, ZKC_TreeDepth>;        
using   zkmint_base_json<snarkT>::zkmint_base_json;

    libzeth::extended_proof<ppT, snarkT>    prove_test(circuitT& aZkp, const typename snarkT::proving_key &proving_key) const;
};

template<typename snarkT>
class zkconsent_base_json {
public:
    zkconsent_base_json() {}
    zkconsent_base_json(const boost::filesystem::path& jsonfile) { set(jsonfile);  }
    zkconsent_base_json(const boost::json::object& objJSON) { set(objJSON);  }

    zkconsent_base_json<snarkT>& set(const boost::filesystem::path& jsonfile) {
        return LoadZKJson(*this, jsonfile);
    }
    zkconsent_base_json<snarkT>& set(const boost::json::object& objJSON);

    void trace();
protected:
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

template<typename snarkT>
class zkconsent_json: public zkconsent_base_json<snarkT> {
public:
using   circuitT = zkconsent_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, ZKC_TreeDepth>;        
using   zkconsent_base_json<snarkT>::zkconsent_base_json;

    libzeth::extended_proof<ppT, snarkT>    prove_test(circuitT& aZkp, const typename snarkT::proving_key &proving_key) const;
};

template<typename snarkT>
class zkconsent_simp_json: public zkconsent_base_json<snarkT> {
public:
using   circuitT = zkconsent_simp_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, ZKC_TreeDepth>;        
using   zkconsent_base_json<snarkT>::zkconsent_base_json;

    libzeth::extended_proof<ppT, snarkT>    prove_test(circuitT& aZkp, const typename snarkT::proving_key &proving_key) const;
};

template<typename snarkT>
class zkconfconsent_json {
public:
using   circuitT = zkconfconsent_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, ZKC_TreeDepth>;        

    zkconfconsent_json() {}
    zkconfconsent_json(const boost::filesystem::path& jsonfile) { set(jsonfile);  }
    zkconfconsent_json(const boost::json::object& objJSON) { set(objJSON);  }

    zkconfconsent_json<snarkT>& set(const boost::filesystem::path& jsonfile) {
        return LoadZKJson(*this, jsonfile);
    }
    zkconfconsent_json<snarkT>& set(const boost::json::object& objJSON);

    libzeth::extended_proof<ppT, snarkT>    prove_test(circuitT& aZkp, const typename snarkT::proving_key &proving_key) const;

    void trace();

protected:
    std::string a_pk;
    std::string studyid;
    std::string rho;
    std::string trapr;
    bool choice;
};

template<typename snarkT>
class zkconfterminate_json {
public:
using   circuitT = zkconfterminate_wrap<ppT, FieldT, HashT, HashTreeT, snarkT, ZKC_TreeDepth>;        

    zkconfterminate_json() {}
    zkconfterminate_json(const boost::filesystem::path& jsonfile) { set(jsonfile);  }
    zkconfterminate_json(const boost::json::object& objJSON) { set(objJSON);  }

    zkconfterminate_json<snarkT>& set(const boost::filesystem::path& jsonfile) {
        return LoadZKJson(*this, jsonfile);
    }
    zkconfterminate_json<snarkT>& set(const boost::json::object& objJSON);

    libzeth::extended_proof<ppT, snarkT>    prove_test(circuitT& aZkp, const typename snarkT::proving_key &proving_key) const;

    void trace();

protected:
    std::string a_pk;
    std::string rho;
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
 
 #include "zkjson.tcc"

#endif // __ZKJSON_HPP_
