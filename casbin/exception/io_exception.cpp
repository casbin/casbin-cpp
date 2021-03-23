#include "pch.h"

#ifndef IO_EXCEPTION
#define IO_EXCEPTION


#include "./io_exception.h"

IOException :: IOException(string& error_message):error_message(error_message) {
}

IOException ::IOException(const char *erro_message):error_message(erro_message) {

}

#endif //IO_EXCEPTION
