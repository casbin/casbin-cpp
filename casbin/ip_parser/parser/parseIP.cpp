#include "pch.h"

#ifndef PARSEIP_CPP
#define PARSEIP_CPP


#include "./parseIP.h"

namespace casbin {

IP parseIP(const std::string& s) {
    for(int i = 0 ; i < s.length() ; i++) {
        switch(s[i]) {
        case '.':
            return parseIPv4(s);
        case ':':
            return parseIPv6(s);
        }
    }
    IP p;
    p.isLegal = false;
    return p;
}

} // namespace casbin

#endif // PARSEIP_CPP
