#pragma once

#include "pch.h"

#include "./allFF.h"

bool allFF(vector<byte> b) {
    for(int i = 0 ; i < b.size() ; i++){
        if(b[i] != 0xff) {
            return false;
        }
    }
    return true;
}