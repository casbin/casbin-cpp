#ifndef CASBIN_CPP_UTIL_SPLIT
#define CASBIN_CPP_UTIL_SPLIT

#include <string.h>
#include <string>
#include <vector>

#define LARGE 2147483647

using namespace std;

vector <string> split(string str, string del, int limit = 0){
    vector <string> tokens;

    if(limit<=0)
        limit = LARGE;

    for(int i = 1; i < limit ; i++){
        size_t pos = str.find(del);
        if(pos != string::npos){
            tokens.push_back(str.substr(0, pos));
            str = str.substr(pos + del.length());
        } else
            break;
    }
    tokens.push_back(str);

    return tokens;
}

#endif