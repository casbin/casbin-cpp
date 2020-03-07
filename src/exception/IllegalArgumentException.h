#ifndef CASBIN_CPP_EXCEPTION_ILLEGAL_ARGUMENT_EXCEPTION
#define CASBIN_CPP_EXCEPTION_ILLEGAL_ARGUMENT_EXCEPTION

#include <string>

#endif

using namespace std;

// Exception class for unsupported operations.
class IllegalArgumentException{
    string error_message;
    public:
        IllegalArgumentException(string error_message){
            this->error_message = error_message;
        }
};