#pragma once

#include "pch.h"

#include "./illegal_argument_exception.h"

IllegalArgumentException :: IllegalArgumentException(string error_message) {
    this->error_message = error_message;
}