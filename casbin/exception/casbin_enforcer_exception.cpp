#pragma once

#include "pch.h"

#include "./casbin_enforcer_exception.h"

CasbinEnforcerException :: CasbinEnforcerException(string error_message){
    this->error_message = error_message;
}