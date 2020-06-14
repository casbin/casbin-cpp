#ifndef CASBIN_CPP_EXCEPTION_UNSUPPORTED_OPERATION_EXCEPTION
#define CASBIN_CPP_EXCEPTION_UNSUPPORTED_OPERATION_EXCEPTION

#include <string>

using namespace std;

// Exception class for unsupported operations.
class UnsupportedOperationException{
    string error_message;
    public:
        UnsupportedOperationException(string error_message);
};

#endif