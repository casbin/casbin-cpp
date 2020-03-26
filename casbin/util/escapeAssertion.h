#ifndef CASBIN_CPP_UTIL_ESCAPE_ASSERTION
#define CASBIN_CPP_UTIL_ESCAPE_ASSERTION

#include <regex>
#include <string>

using namespace std;

/**
* escapeAssertion escapes the dots in the assertion, because the expression evaluation doesn't support such variable names.
*
* @param s the value of the matcher and effect assertions.
* @return the escaped value.
*/
string escapeAssertion(string s) {
    //Replace the first dot, because the string doesn't start with "m="
    // and is not covered by the regex.
    if (s.find("r")==0 || s.find("p")==0) {
        int pos = s.find("\\.");
        s = s.replace(pos, 2, "_");
    }

    regex regex_s("(\\|| |=|\\)|\\(|&|<|>|,|\\+|-|!|\\*|\\/)(r|p)\\.");
    smatch match;

    if (regex_search(s, match, regex_s)) {
        for (int i=1; i<match.size(); i++) {
            int pos = match.str(i).find(".");
            string newStr = match.str(i).replace(pos, 1, "_");
            s = s.replace(match.position(i), match.str(i).length(), newStr);
        }
    }
    return s;
}

#endif