#pragma once

#include "pch.h"

#include "./unsupported_operation_exception.h"

UnsupportedOperationException :: UnsupportedOperationException(string error_message) {
    this->error_message = error_message;
}