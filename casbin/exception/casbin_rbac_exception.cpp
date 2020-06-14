#pragma once

#include "pch.h"

#include "./casbin_rbac_exception.h"

CasbinRBACException :: CasbinRBACException(string error_message){
    this->error_message = error_message;
}