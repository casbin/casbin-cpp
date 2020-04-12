#include "exceptions.h"
using namespace std;
Error::Error()
{
    isNull = true;
}

Error::Error(string info)
{
    error_info = info;
    isNull = false;
}

string Error::Info()
{
    return error_info;
}

bool Error::IsNull()
{
    return isNull;
}