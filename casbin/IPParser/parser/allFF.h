#ifndef IP_PARSER_PARSER_ALL_FF
#define IP_PARSER_PARSER_ALL_FF

#include <vector>

#include "./Byte.h"

using namespace std;

bool allFF(vector < Byte > b) {
    for(int i = 0 ; i < b.size() ; i++){
        if(b[i] != 0xff) {
            return false;
        }
    }
	return true;
}

#endif