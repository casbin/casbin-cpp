#ifndef CASBIN_CPP_EXCEPTION_CASBIN_RBAC_EXCEPTION
#define CASBIN_CPP_EXCEPTION_CASBIN_RBAC_EXCEPTION

#include <string>

using namespace std;

// Exception class for Casbin Adapter Exception.
class CasbinRBACException{
    string error_message;
    public:
        CasbinRBACException(string error_message);
};

#endif