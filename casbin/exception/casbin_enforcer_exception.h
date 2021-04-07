#ifndef CASBIN_CPP_EXCEPTION_CASBIN_ENFORCER_EXCEPTION
#define CASBIN_CPP_EXCEPTION_CASBIN_ENFORCER_EXCEPTION

#include <string>

namespace casbin {

// Exception class for Casbin Enforcer Exception.
class CasbinEnforcerException{
    std::string error_message;
    public:
        CasbinEnforcerException(std::string error_message);
};

} // namespace casbin

#endif