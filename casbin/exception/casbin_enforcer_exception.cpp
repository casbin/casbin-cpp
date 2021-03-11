#include "pch.h"

#ifndef CASBIN_ENFORCER_EXCEPTION_CPP
#define CASBIN_ENFORCER_EXCEPTION_CPP


#include "./casbin_enforcer_exception.h"

CasbinEnforcerException :: CasbinEnforcerException(string error_message){
    this->error_message = error_message;
}

#endif // CASBIN_ENFORCER_EXCEPTION_CPP
