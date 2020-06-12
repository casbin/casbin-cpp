#pragma once

#include "pch.h"

#include "./xtoi.h"

pair<int, int> xtoi(string s) {
    int n = 0;
    int i = 0;
    pair <int, int> p;
    for(i = 0 ; i < s.length() ; i++) {
        if('0' <= s[i] && s[i] <= '9') {
            n *= 16;
            n += int(s[i] - '0');
        } else if('a' <= s[i] && s[i] <= 'f') {
            n *= 16;
            n += int(s[i]-'a') + 10;
        } else if('A' <= s[i] && s[i] <= 'F') {
            n *= 16;
            n += int(s[i]-'A') + 10;
        } else {
            break;
        }
        if(n >= big) {
            p.first = 0;
            p.second = i;
            return p;
        }
    }
    if(i == 0) {
        p.first = 0;
        p.second = i;
        return p;
    }
    p.first = n;
    p.second = i;
    return p;
}