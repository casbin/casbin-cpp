#pragma once

#include "pch.h"

#include "./parser_exception.h"

ParserException :: ParserException(string error_message){
    this->error_message = error_message;
}