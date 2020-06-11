#pragma once

#include "pch.h"

#include "./util.h"

using namespace std;

// ArrayEquals determines whether two string arrays are identical.
bool ArrayEquals(vector<string> a, vector<string> b) {
    if (a.size() != b.size()) {
        return false;
    }

    for (int i = 0 ; i < a.size() ; i++) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}