#pragma once

#include "pch.h"

#include "./util.h"

using namespace std;

string& LTrim(string& str, const string& chars) {
    str.erase(0, str.find_first_not_of(chars));
    return str;
}
 
string& RTrim(string& str, const string& chars) {
    str.erase(str.find_last_not_of(chars) + 1);
    return str;
}
 
string Trim(string& str, const string& chars) {
    return LTrim(RTrim(str, chars), chars);
}