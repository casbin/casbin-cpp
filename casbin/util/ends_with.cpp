#pragma once

#include "pch.h"

#include "./util.h"

using namespace std;

bool EndsWith(string base, string suffix){
    int base_len = int(base.length());
    int suffix_len = int(suffix.length());
    return base.substr(base_len-suffix_len, suffix_len).compare(suffix) == 0;
}