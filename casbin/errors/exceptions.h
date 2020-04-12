#pragma once

#ifdef CASBIN_EXPORTS
#define ERROR_API __declspec(dllexport)
#else
#define ERROR_API __declspec(dllimport)
#endif

#include <string>

using std::string;


class ERROR_API Error {
public:
    string error_info;
    bool isNull;

    Error();
    Error(string info);
    string Info();
    bool IsNull();
};
