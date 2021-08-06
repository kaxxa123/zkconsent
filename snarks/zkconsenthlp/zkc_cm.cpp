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

#include "zkc_helpers.hpp"
#include "cm_extra_gadgets.hpp"
#include "zkc_cm.hpp"
#include "zkc_params.hpp"

namespace libzkconsent
{

std::string     CMMid(const std::string& a_pk, const std::string& rho)
{
    return comm_id_gadget<FieldT, HashT>::get_id_comm(a_pk, rho);    
}

}
