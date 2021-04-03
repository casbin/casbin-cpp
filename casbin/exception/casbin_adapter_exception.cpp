#include "pch.h"

#ifndef CASBIN_ADAPTER_EXCEPTION_CPP
#define CASBIN_ADAPTER_EXCEPTION_CPP


#include "./casbin_adapter_exception.h"

namespace casbin {

CasbinAdapterException :: CasbinAdapterException(std::string error_message) {
    this->error_message = error_message;
}

} // namespace casbin

#endif // CASBIN_ADAPTER_EXCEPTION_CPP
