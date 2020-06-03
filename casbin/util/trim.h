#ifndef CASBIN_CPP_UTIL_TRIM
#define CASBIN_CPP_UTIL_TRIM

#include <string>

using namespace std;

string& LTrim(string& str, const string& chars = "\t\n\v\f\r ") {
    str.erase(0, str.find_first_not_of(chars));
    return str;
}
 
string& RTrim(string& str, const string& chars = "\t\n\v\f\r ") {
    str.erase(str.find_last_not_of(chars) + 1);
    return str;
}
 
string Trim(string& str, const string& chars = "\t\n\v\f\r ") {
    return LTrim(RTrim(str, chars), chars);
}

#endif