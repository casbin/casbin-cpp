#include "pch.h"

#ifndef IO_EXCEPTION
#define IO_EXCEPTION


#include "./io_exception.h"

IOException :: IOException(string error_message) {
    this->error_message = error_message;
}

#endif //IO_EXCEPTION
