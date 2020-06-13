#pragma once

#include "pch.h"

#include <regex>

#include "./util.h"

using namespace std;

/**
* escapeAssertion escapes the dots in the assertion, because the expression evaluation doesn't support such variable names.
*
* @param s the value of the matcher and effect assertions.
* @return the escaped value.
*/
string EscapeAssertion(string s) {
    regex regex_s("[a-zA-Z0-9. ]+");

    sregex_iterator words_begin = sregex_iterator(s.begin(), s.end(), regex_s); 
    auto words_end = sregex_iterator();

    for (sregex_iterator k = words_begin ; k != words_end ; ++k) {
        smatch match = *k;
        string match_str = match.str();
        int pos = int(match_str.find("."));
        if(pos!=-1){
            string new_str = match_str.replace(pos, 1, "_");
            s = s.replace(match.position(), match.str().length(), new_str);
        }
    }

    return s;
}