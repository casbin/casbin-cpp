#pragma once

#include "pch.h"

#include "./util.h"

using namespace std;

string Join(vector<string> vos, string sep){
    string fs = vos[0];
    for (int i = 1 ; i < vos.size() ; i++)
        fs += sep + vos[i];
    return fs;
}