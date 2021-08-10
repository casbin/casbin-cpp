#include "pch.h"

#ifndef EQUAL_CPP
#define EQUAL_CPP


#include "./equal.h"

namespace casbin {

bool equal(const IPMask& m1, const IPMask& m2) {
    if(m1.size() != m2.size())
        return false;
    for(int i = 0 ; i < m1.size() ; i++) {
        if(m1[i] != m2[i] )
            return false;
    }
    return true;
}

} // namespace casbin

#endif // EQUAL_CPP
