#ifndef CASBIN_CPP_EXCEPTION_ILLEGAL_ARGUMENT_EXCEPTION
#define CASBIN_CPP_EXCEPTION_ILLEGAL_ARGUMENT_EXCEPTION

#include <string>

using namespace std;

// Exception class for illegal arguments.
class IllegalArgumentException{
    string error_message;
    public:
        IllegalArgumentException(string error_message);
};

#endif