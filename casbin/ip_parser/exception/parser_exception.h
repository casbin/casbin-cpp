#ifndef IP_PARSER_EXCEPTIONS_PARSE_EXCEPTION
#define IP_PARSER_EXCEPTIONS_PARSE_EXCEPTION

#include <string>

using namespace std;

class ParserException{
    string error_message;
    public:
        explicit ParserException(string& error_message);
        explicit ParserException(const char* error_message);
        explicit ParserException(const string& error_message);
};

#endif