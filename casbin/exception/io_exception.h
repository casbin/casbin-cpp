#ifndef CASBIN_CPP_EXCEPTION_IO_EXCEPTION
#define CASBIN_CPP_EXCEPTION_IO_EXCEPTION

#include <string>

namespace casbin {

// Exception class for I/O operations.
class IOException{
    std::string error_message;
    public:
        IOException(std::string error_message);
};

} // namespace casbin

#endif