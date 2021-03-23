#ifndef CASBIN_CPP_EXCEPTION_CASBIN_ENFORCER_EXCEPTION
#define CASBIN_CPP_EXCEPTION_CASBIN_ENFORCER_EXCEPTION

#include <string>

using namespace std;

// Exception class for Casbin Enforcer Exception.
class CasbinEnforcerException{
    string error_message;
    public:
        explicit CasbinEnforcerException(string& error_message);
        explicit CasbinEnforcerException(const char* error_message);
};

#endif