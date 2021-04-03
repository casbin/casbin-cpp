#ifndef CASBIN_CPP_EXCEPTION_ILLEGAL_ARGUMENT_EXCEPTION
#define CASBIN_CPP_EXCEPTION_ILLEGAL_ARGUMENT_EXCEPTION

#include <string>

namespace casbin {

// Exception class for illegal arguments.
class IllegalArgumentException{
    std::string error_message;
    public:
        IllegalArgumentException(std::string error_message);
};

} // namespace casbin

#endif