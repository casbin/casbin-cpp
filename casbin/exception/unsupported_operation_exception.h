#ifndef CASBIN_CPP_EXCEPTION_UNSUPPORTED_OPERATION_EXCEPTION
#define CASBIN_CPP_EXCEPTION_UNSUPPORTED_OPERATION_EXCEPTION

#include <string>

namespace casbin {

// Exception class for unsupported operations.
class UnsupportedOperationException{
    std::string error_message;
    public:
        UnsupportedOperationException(std::string error_message);
};

} // namespace casbin

#endif