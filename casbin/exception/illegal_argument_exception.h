#ifndef CASBIN_CPP_EXCEPTION_ILLEGAL_ARGUMENT_EXCEPTION
#define CASBIN_CPP_EXCEPTION_ILLEGAL_ARGUMENT_EXCEPTION

#include <string>

using namespace std;

// Exception class for illegal arguments.
class IllegalArgumentException{
    string error_message;
    public:
        //explicit IllegalArgumentException(string error_message);
        explicit IllegalArgumentException(string& error_message);
        explicit IllegalArgumentException(const char* error_message);
        explicit IllegalArgumentException(const string& error_message);
        
};

#endif