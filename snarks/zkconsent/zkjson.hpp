#ifndef __ZKJSON_HPP_
#define __ZKJSON_HPP_

template<class jsonT>
jsonT&  LoadZKJson(jsonT& zkjson, const boost::filesystem::path& jsonfile);

class zkconfirm_json {
public:
    zkconfirm_json() {}
    zkconfirm_json(const boost::filesystem::path& jsonfile) { set(jsonfile);  }
    zkconfirm_json(const boost::json::object& objJSON) { set(objJSON);  }

    zkconfirm_json& set(const boost::filesystem::path& jsonfile) {
        return LoadZKJson(*this, jsonfile);
    }
    zkconfirm_json& set(const boost::json::object& objJSON);
    void trace();

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
