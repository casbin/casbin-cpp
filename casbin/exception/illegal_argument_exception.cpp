#include "pch.h"

#ifndef ILLEGAL_ARGUMENT_EXCEPTION_CPP
#define ILLEGAL_ARGUMENT_EXCEPTION_CPP

#include "./illegal_argument_exception.h"

namespace casbin {

IllegalArgumentException :: IllegalArgumentException(std::string error_message) {
    this->error_message = error_message;
}

} // namespace casbin

#endif // ILLEGAL_ARGUMENT_EXCEPTION_CPP
