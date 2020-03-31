#ifndef CASBIN_CPP_UTIL_JOIN_SLICE
#define CASBIN_CPP_UTIL_JOIN_SLICE

#include <vector>
#include <string>

using namespace std;

vector<string> joinSlice(string a, vector<string> slice) {
    vector <string> result{a};
    for(int i = 0 ; i < slice.size() ; i++)
        result.push_back(slice[i]);
    return result;
}

#endif