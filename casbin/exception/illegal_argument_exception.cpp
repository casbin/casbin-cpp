#include "pch.h"

#ifndef ILLEGAL_ARGUMENT_EXCEPTION_CPP
#define ILLEGAL_ARGUMENT_EXCEPTION_CPP


#include "./illegal_argument_exception.h"
IllegalArgumentException :: IllegalArgumentException(string& error_message):error_message(error_message) {
}

IllegalArgumentException :: IllegalArgumentException(const char *error_message):error_message(error_message) {

}

IllegalArgumentException :: IllegalArgumentException(const string &error_message):error_message(error_message) {

}

#endif // ILLEGAL_ARGUMENT_EXCEPTION_CPP
