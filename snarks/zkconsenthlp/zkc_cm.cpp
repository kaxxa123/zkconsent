#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <vector>

#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/circuits/prfs/prf.hpp"
#include "libzeth/core/utils.hpp"
#include "libzeth/zeth_constants.hpp"

#include "zkc_params.hpp"
#include "zkc_helpers.hpp"
#include "extra_cm_gadgets.hpp"
#include "zkc_cm.hpp"

namespace libzkconsent
{

std::string     CMMid(const std::string& a_pk, const std::string& rho)
{
    return comm_id_gadget<FieldT, HashT>::get_cm(a_pk, rho);    
}

std::string     CMMconsent(
                    const std::string& sapk, 
                    const std::string& srho,
                    const std::string& strap_r,
                    const std::string& sid,
                    bool bChoice)
{
    return comm_consent_gadget<FieldT, HashT>::get_cm(sapk, srho, strap_r, sid, bChoice);    
}

std::string      FieldBound(const std::string& value)
{
    FieldT fval = FieldT(value.c_str());
    return FieldtoString(fval);
}

}
