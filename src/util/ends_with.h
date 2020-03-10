#ifndef CASBIN_CPP_UTIL_ENDS_WITH
#define CASBIN_CPP_UTIL_ENDS_WITH

#include <string>

using namespace std;

bool ends_with(string base, string suffix){
    int base_len = base.length();
    int suffix_len = suffix.length();
    return base.substr(base_len-suffix_len, suffix_len).compare(suffix) == 0;
}

#endif