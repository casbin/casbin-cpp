#ifndef CASBIN_CPP_UTIL_SET_SUBTRACT
#define CASBIN_CPP_UTIL_SET_SUBTRACT

#include <vector>
#include <string>
#include <unordered_map>

using namespace std;

// SetSubtract returns the elements in `a` that aren't in `b`.
vector<string> SetSubtract(vector<string> a, vector<string> b) {
    unordered_map<string, bool> mb;

    for (int i = 0 ; i < b.size() ; i++)
        mb[b[i]] = true;

    vector<string> diff;
    for (int i = 0 ; i < a.size() ; i++)
        if (!mb[a[i]])
            diff.push_back(a[i]);
	return diff;
}

#endif