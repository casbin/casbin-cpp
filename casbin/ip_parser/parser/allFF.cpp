#include "pch.h"

#ifndef ALLFF_CPP
#define ALLFF_CPP


#include "./allFF.h"

bool allFF(vector<byte> b) {
    for(int i = 0 ; i < b.size() ; i++){
        if(b[i] != 0xff) {
            return false;
        }
    }
    return true;
}

#endif // ALLFF_CPP
