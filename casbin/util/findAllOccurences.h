#ifndef CASBIN_CPP_UTIL_FIND_ALL_OCCURENCES
#define CASBIN_CPP_UTIL_FIND_ALL_OCCURENCES

#include <string>
#include <vector>

using namespace std;

vector <size_t> findAllOccurances(string data, string toSearch){
	// Get the first occurrence
	size_t pos = data.find(toSearch);

    vector <size_t> vec;

	// Repeat till end is reached
	while( pos != std::string::npos)
	{
		// Add position to the vector
		vec.push_back(pos);
 
		// Get the next occurrence from the current position
		pos =data.find(toSearch, pos + toSearch.size());
	}
    return vec;
}

#endif