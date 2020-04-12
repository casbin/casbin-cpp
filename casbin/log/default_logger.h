#pragma once
#include "logger.h"
class DefaultLogger
{
private:
    bool enabled = true;
public:
    void SetEnable(bool enabled);

    bool IsEnable();

    template <typename... Object>
    void Printf(string s, Object... objects);

    template <typename... Object>
    void Print(Object... objects);
};