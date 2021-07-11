#include "pch.h"

#ifndef ALLFF_CPP
#define ALLFF_CPP


#include "./allFF.h"

namespace casbin {

bool allFF(std::vector<byte> b) {
    for(int i = 0 ; i < b.size() ; i++) {
        if(b[i] != 0xff) {
            return false;
        }
    }
    return true;
}

} // namespace casbin

#endif // ALLFF_CPP
