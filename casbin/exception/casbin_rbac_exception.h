#ifndef CASBIN_CPP_EXCEPTION_CASBIN_RBAC_EXCEPTION
#define CASBIN_CPP_EXCEPTION_CASBIN_RBAC_EXCEPTION

#include <string>

using namespace std;

// Exception class for Casbin Adapter Exception.
class CasbinRBACException{
    string error_message;
    public:
        explicit CasbinRBACException(string& error_message);
        explicit CasbinRBACException(const char* error_message);
};

#endif