#ifndef CASBIN_CPP_EXCEPTION_CASBIN_RBAC_EXCEPTION
#define CASBIN_CPP_EXCEPTION_CASBIN_RBAC_EXCEPTION

#include <string>

namespace casbin {

// Exception class for Casbin Adapter Exception.
class CasbinRBACException{
    std::string error_message;
    public:
        CasbinRBACException(std::string error_message);
};

} // namespace casbin

#endif