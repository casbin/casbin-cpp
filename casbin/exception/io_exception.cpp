#include "pch.h"

#ifndef IO_EXCEPTION
#define IO_EXCEPTION


#include "./io_exception.h"

namespace casbin {

IOException :: IOException(std::string error_message) {
    this->error_message = error_message;
}

} // namespace casbin

#endif //IO_EXCEPTION
