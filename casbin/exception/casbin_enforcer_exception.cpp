#include "pch.h"

#ifndef CASBIN_ENFORCER_EXCEPTION_CPP
#define CASBIN_ENFORCER_EXCEPTION_CPP

#include "./casbin_enforcer_exception.h"

namespace casbin {

CasbinEnforcerException :: CasbinEnforcerException(std::string error_message){
    this->error_message = error_message;
}

} // namespace casbin

#endif // CASBIN_ENFORCER_EXCEPTION_CPP
