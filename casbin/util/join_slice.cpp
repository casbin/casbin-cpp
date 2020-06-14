#pragma once

#include "pch.h"

#include "./util.h"

using namespace std;

vector<string> JoinSlice(string a, vector<string> slice) {
    vector<string> result{a};
    for (int i = 0 ; i < slice.size() ; i++)
        result.push_back(slice[i]);
    return result;
}