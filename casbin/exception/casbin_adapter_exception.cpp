#include "pch.h"

#ifndef CASBIN_ADAPTER_EXCEPTION_CPP
#define CASBIN_ADAPTER_EXCEPTION_CPP


#include "./casbin_adapter_exception.h"

CasbinAdapterException :: CasbinAdapterException(string& error_message): error_message(error_message) {
}

CasbinAdapterException ::CasbinAdapterException(const char *error_message): error_message(error_message) {

}

#endif // CASBIN_ADAPTER_EXCEPTION_CPP
