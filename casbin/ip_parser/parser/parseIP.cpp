#pragma once

#include "pch.h"

#include "./parseIP.h"

IP parseIP(string s) {
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