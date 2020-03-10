#ifndef CASBIN_CPP_UTIL_REMOVE_COMMENTS
#define CASBIN_CPP_UTIL_REMOVE_COMMENTS

#include <string>

#include "./trim.h"

using namespace std;

// RemoveComments removes the comments starting with # in the text.
string removeComments(string s) {
	size_t pos = s.find("#");
	if(pos == string::npos) {
		return s;
	}
    string finStr = s.substr(0, pos);
	return trim(finStr);
}

#endif