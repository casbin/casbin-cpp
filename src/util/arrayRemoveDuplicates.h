#ifndef CASBIN_CPP_UTIL_ARRAY_REMOVE_DUPLICATES
#define CASBIN_CPP_UTIL_ARRAY_REMOVE_DUPLICATES

#include <string>
#include <vector>
#include <unordered_map>

using namespace std;

// ArrayRemoveDuplicates removes any duplicated elements in a string array.
void arrayRemoveDuplicates(vector <string> &s) {
    unordered_map <string, bool> found;
	int j = 0;
    for(int i = 0 ; i < s.size() ; i++){
        if(!found[s[i]]) {
			found[s[i]] = true;
			s[j] = s[i];
			j++;
		}
    }
    s = vector <string> (s.begin(), s.begin()+j);
}

#endif