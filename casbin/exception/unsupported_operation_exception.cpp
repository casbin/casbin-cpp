#include "pch.h"

#ifndef UNSUPPORTED_OPERATION_EXCEPTION_CPP
#define UNSUPPORTED_OPERATION_EXCEPTION_CPP


#include "./unsupported_operation_exception.h"

UnsupportedOperationException :: UnsupportedOperationException(string error_message) {
    this->error_message = error_message;
}

#endif // UNSUPPORTED_OPERATION_EXCEPTION_CPP
