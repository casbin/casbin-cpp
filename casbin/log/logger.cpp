#include "pch.h"

#ifndef LOGGER_CPP
#define LOGGER_CPP

#include "Logger.h"
#include "log_util.h"

namespace casbin {

//Print formats using the default formats for its operands and logs the message.
template <typename T, typename... Object>
void Logger::Print(T arg, Object... objects) {
    return;
}

//Printf formats according to a format specifier and logs the message.
template <typename... Object>
void Logger::Printf(std::string format, Object... objects) {
    Print(objects...);
}

DefaultLogger LogUtil::s_logger;

}

#endif // LOGGER_CPP
