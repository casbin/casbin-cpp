#ifndef CASBIN_CPP_EXCEPTION_CASBIN_ADAPTER_EXCEPTION
#define CASBIN_CPP_EXCEPTION_CASBIN_ADAPTER_EXCEPTION

#include <string>

using namespace std;

// Exception class for Casbin Adapter Exception.
class CasbinAdapterException{
    string error_message;
    public:
        explicit CasbinAdapterException(string& error_message);
        explicit CasbinAdapterException(const char* error_message);
};

#endif