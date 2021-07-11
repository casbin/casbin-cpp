#include "pch.h"

#ifndef PRINT_CPP
#define PRINT_CPP


#include "./Print.h"

namespace casbin {

void Print(IP ip_addr) {
    for(int i = 0 ; i < ip_addr.ip.size() ; i++) {
        std::cout << ip_addr.ip[i] << " ";
    }
    std::cout << std::endl;
    std::cout << "Status : " << ip_addr.isLegal << std::endl;
}

} // namespace casbin

#endif // PRINT_CPP
