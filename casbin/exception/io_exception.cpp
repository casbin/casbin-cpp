#pragma once

#include "pch.h"

#include "./io_exception.h"

IOException :: IOException(string error_message) {
    this->error_message = error_message;
}