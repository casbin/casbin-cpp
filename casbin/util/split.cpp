#pragma once

#include "pch.h"

#include <string.h>

#include "./util.h"

#define LARGE 2147483647

using namespace std;

vector<string> Split(string str, string del, int limit){
    vector<string> tokens;

    if(limit<=0)
        limit = LARGE;

    for (int i = 1; i < limit ; i++) {
        size_t pos = str.find(del);
        if (pos != string::npos) {
            tokens.push_back(str.substr(0, pos));
            str = str.substr(pos + del.length());
        } else
            break;
    }
    tokens.push_back(str);

    return tokens;
}