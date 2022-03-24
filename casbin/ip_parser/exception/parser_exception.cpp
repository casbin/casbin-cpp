#include "casbin/pch.h"

#ifndef PARSER_EXCEPTION_CPP
#define PARSER_EXCEPTION_CPP

#include "casbin/ip_parser/exception/parser_exception.h"

namespace casbin {

ParserException ::ParserException(std::string error_message) {
    this->error_message = error_message;
}

} // namespace casbin

#endif // PARSER_EXCEPTION_CPP
