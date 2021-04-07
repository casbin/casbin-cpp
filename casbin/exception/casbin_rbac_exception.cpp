#include "pch.h"

#ifndef CASBIN_RBAC_EXCEPTION_CPP
#define CASBIN_RBAC_EXCEPTION_CPP


#include "./casbin_rbac_exception.h"

namespace casbin {

CasbinRBACException :: CasbinRBACException(std::string error_message){
    this->error_message = error_message;
}

} // namespace casbin

#endif // CASBIN_RBAC_EXCEPTION_CPP
