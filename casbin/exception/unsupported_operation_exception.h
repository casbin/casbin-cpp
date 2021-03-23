#ifndef CASBIN_CPP_EXCEPTION_UNSUPPORTED_OPERATION_EXCEPTION
#define CASBIN_CPP_EXCEPTION_UNSUPPORTED_OPERATION_EXCEPTION

#include <string>

using namespace std;

// Exception class for unsupported operations.
class UnsupportedOperationException{
    string error_message;
    public:
        explicit UnsupportedOperationException(string& error_message);
        explicit UnsupportedOperationException(const char* error_message);
};

#endif