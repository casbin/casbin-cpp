#include "pch.h"

#ifndef PRINT_CPP
#define PRINT_CPP


#include "./Print.h"

void Print(IP ip_addr) {
    for(auto i = 0 ; i < ip_addr.ip.size() ; i++){
        cout<<ip_addr.ip[i]<<" ";
    }
    cout<<endl;
    cout<<"Status : "<<ip_addr.isLegal<<endl;
}

#endif // PRINT_CPP
