#ifndef IP_PARSER_EXCEPTIONS_PARSE_EXCEPTION
#define IP_PARSER_EXCEPTIONS_PARSE_EXCEPTION

#include <string>

using namespace std;

class ParserException{
    string error_message;
    public:
        ParserException(string error_message);
};

#endif