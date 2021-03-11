#include "pch.h"

#ifndef CASBIN_RBAC_EXCEPTION_CPP
#define CASBIN_RBAC_EXCEPTION_CPP


#include "./casbin_rbac_exception.h"

CasbinRBACException :: CasbinRBACException(string error_message){
    this->error_message = error_message;
}

#endif // CASBIN_RBAC_EXCEPTION_CPP
