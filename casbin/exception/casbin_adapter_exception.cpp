#pragma once

#include "pch.h"

#include "./casbin_adapter_exception.h"

CasbinAdapterException :: CasbinAdapterException(string error_message) {
    this->error_message = error_message;
}