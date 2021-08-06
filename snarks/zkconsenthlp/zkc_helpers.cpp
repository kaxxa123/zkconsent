#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <vector>

#include "zkc_helpers.hpp"

namespace libzkconsent
{

std::string digest2hex(const std::vector<bool>& digest)
{
    std::string strOut;

    //digest is made up of a sequence of bytes hence
    //the size must be a factor of 8
    if (digest.size() % 8)
        return strOut;

    for (size_t pos = 0; pos+3 < digest.size(); pos += 4)
    {
        uint fourBits = digest[pos] ? 8 : 0;
        fourBits += digest[pos + 1] ? 4 : 0;
        fourBits += digest[pos + 2] ? 2 : 0;
        fourBits += digest[pos + 3] ? 1 : 0;
        
        if (fourBits < 10)
                strOut += (char)('0'+fourBits); 
        else    strOut += (char)('A'+fourBits-10);    
    }

    return strOut;
}

}
