#pragma once

#include "pch.h"

#include "./equal.h"

bool equal(IPMask m1, IPMask m2) {
    if(m1.size() != m2.size())
        return false;
    for(int i = 0 ; i < m1.size() ; i++) {
        if(m1[i] != m2[i] )
            return false;
    }
    return true;
}