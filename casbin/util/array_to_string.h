#ifndef CASBIN_CPP_UTIL_ARRAY_TO_STRING
#define CASBIN_CPP_UTIL_ARRAY_TO_STRING

#include <vector>
#include <string>

using namespace std;

string ArrayToString(vector<string> arr){
    string res = arr[0];
    for (int i = 0 ; i < arr.size() ; i++)
        res += ", " + arr[i];
    return res;
}

#endif