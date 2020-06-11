#pragma once

#include "pch.h"

#include <unordered_map>

#include "./util.h"

using namespace std;

// SetSubtract returns the elements in `a` that aren't in `b`.
vector<string> SetSubtract(vector<string> a, vector<string> b) {
    unordered_map<string, bool> mb;

    for (int i = 0 ; i < b.size() ; i++)
        mb[b[i]] = true;

    vector<string> diff;
    for (int i = 0 ; i < a.size() ; i++)
        if (!mb[a[i]])
            diff.push_back(a[i]);
    return diff;
}