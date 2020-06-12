#pragma once

#include "pch.h"

#include "./dtoi.h"

// Decimal to integer.
// Returns number, characters consumed, success.
pair<int, int> dtoi(string s) {
    int n = 0;
    int i = 0;
    pair <int,int > p;
    for(; i < s.length() && s[i] >= '0' && s[i] <= '9'; i++) {
        n = n*10 + int(s[i]-'0');
        if(n >= big) {
            p.first = big;
            p.second = i;
            return p;
        }
    }
    if(i == 0){
        p.first = 0;
        p.second = 0;
        return p;
    }
    p.first = n;
    p.second = i;
    return p;
}