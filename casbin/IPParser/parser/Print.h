#ifndef IP_PARSER_PARSER_PRINT
#define IP_PARSER_PARSER_PRINT

#include <iostream>

#include "./IP.h"

using namespace std;

void Print(IP ip_addr) {
    for(int i = 0 ; i < ip_addr.ip.size() ; i++){
        cout<<ip_addr.ip[i]<<" ";
    }
    cout<<endl;
    cout<<"Status : "<<ip_addr.isLegal<<endl;
}

#endif