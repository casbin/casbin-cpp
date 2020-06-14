#pragma once

#include "pch.h"

#include "./Print.h"

void Print(IP ip_addr) {
    for(int i = 0 ; i < ip_addr.ip.size() ; i++){
        cout<<ip_addr.ip[i]<<" ";
    }
    cout<<endl;
    cout<<"Status : "<<ip_addr.isLegal<<endl;
}