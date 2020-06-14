#ifndef CASBIN_CPP_EXCEPTION_IO_EXCEPTION
#define CASBIN_CPP_EXCEPTION_IO_EXCEPTION

#include <string>

using namespace std;

// Exception class for I/O operations.
class IOException{
    string error_message;
    public:
        IOException(string error_message);
};

#endif