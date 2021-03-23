#include "pch.h"

#ifndef PARSER_EXCEPTION_CPP
#define PARSER_EXCEPTION_CPP


#include "./parser_exception.h"

ParserException :: ParserException(string& error_message):error_message(error_message) {
}

ParserException ::ParserException(const char *error_message):error_message(error_message) {

}

ParserException ::ParserException(const string &error_message):error_message(error_message) {

}

#endif // PARSER_EXCEPTION_CPP
