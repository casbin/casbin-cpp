#ifndef CASBIN_CPP_EXCEPTION_CASBIN_ADAPTER_EXCEPTION
#define CASBIN_CPP_EXCEPTION_CASBIN_ADAPTER_EXCEPTION

#include <string>

namespace casbin {

// Exception class for Casbin Adapter Exception.
class CasbinAdapterException{
    std::string error_message;
    public:
        CasbinAdapterException(std::string error_message);
};

} // namespace casbin

#endif