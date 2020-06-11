#pragma once

#include "pch.h"

#include "./util.h"

using namespace std;

string ArrayToString(vector<string> arr){
    string res = arr[0];
    for (int i = 0 ; i < arr.size() ; i++)
        res += ", " + arr[i];
    return res;
}