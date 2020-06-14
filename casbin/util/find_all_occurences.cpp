#pragma once

#include "pch.h"

#include "./util.h"

using namespace std;

vector <size_t> FindAllOccurences(string data, string toSearch){
    // Get the first occurrence
    size_t pos = data.find(toSearch);

    vector<size_t> vec;

    // Repeat till end is reached
    while (pos != std::string::npos) {
        // Add position to the vector
        vec.push_back(pos);

        // Get the next occurrence from the current position
        pos = data.find(toSearch, pos + toSearch.size());
    }
    return vec;
}