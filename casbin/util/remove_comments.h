#ifndef CASBIN_CPP_UTIL_REMOVE_COMMENTS
#define CASBIN_CPP_UTIL_REMOVE_COMMENTS

#include <string>

#include "./trim.h"

using namespace std;

// RemoveComments removes the comments starting with # in the text.
string RemoveComments(string s) {
    size_t pos = s.find("#");
    if (pos == string::npos)
        return s;
    string fin_str = s.substr(0, pos);
    return Trim(fin_str);
}

#endif