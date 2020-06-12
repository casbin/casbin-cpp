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
    //Replace the first dot, because the string doesn't start with "m="
    // and is not covered by the regex.
    if (s.find("r")==0 || s.find("p")==0) {
        int pos = int(s.find("."));
        s = s.replace(pos, 1, "_");
    }

    regex regex_s("(\\|| |=|\\)|\\(|&|<|>|,|\\+|-|!|\\*|\\/)(r|p)\\.");
    smatch match;

    if (regex_search(s, match, regex_s)) {
        for (int i=1; i<match.size(); i++) {
            int pos = int(match.str(i).find("."));
            string new_str = match.str(i).replace(pos, 1, "_");
            s = s.replace(match.position(i), match.str(i).length(), new_str);
        }
    }
    return s;
}