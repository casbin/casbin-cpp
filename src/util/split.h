#ifndef CASBIN_CPP_UTIL_SPLIT
#define CASBIN_CPP_UTIL_SPLIT

#include <string.h>
#include <string>
#include <vector>

using namespace std;

vector <string> split(string str, string del){
    char *str_arr = (char *)str.c_str();
    char *del_arr = (char *)del.c_str();

    char *token = strtok(str_arr, del_arr);
    
    vector <string> tokens;
    while (token != NULL){ 
        tokens.push_back(string(token));
        token = strtok(NULL, del_arr);
    }
    return tokens;
}

#endif