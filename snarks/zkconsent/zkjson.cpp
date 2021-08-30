#include <stdlib.h>
#include <iostream>
#include <boost/filesystem.hpp>
#include <boost/json.hpp>
#include "zkjson.hpp"

zkconfirm_json& zkconfirm_json::set(const boost::json::object& objJSON)
{
    extract(objJSON, a_pk, "a_pk");
    extract(objJSON, studyid, "studyid");
    extract(objJSON, rho, "rho");
    extract(objJSON, trapr, "trapr");
    extract(objJSON, choice, "choice");;

    return (*this);
}

void zkconfirm_json::trace()
{
    std::cout << " a_pk:    " << a_pk << std::endl;
    std::cout << " studyid: " << studyid << std::endl;
    std::cout << " rho:     " << rho << std::endl;
    std::cout << " trapr:   " << trapr << std::endl;
    std::cout << " choice:  " << choice << std::endl;
}

