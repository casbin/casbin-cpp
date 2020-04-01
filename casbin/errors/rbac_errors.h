#pragma once

#include <exception>

using namespace std;

struct ERR_NAME_NOT_FOUND : public exception {
	[[nodiscard]] const char* what() const noexcept override
	{
        return "error: name does not exist";
    }
};

struct ERR_DOMAIN_PARAMETER : public exception {
	[[nodiscard]] const char* what() const noexcept override
    {
        return "error: domain should be 1 parameter";
    }
};

struct ERR_NAMES12_NOT_FOUND : public exception {
	[[nodiscard]] const char* what() const noexcept override
	{
        return "error: name1 or name2 does not exist";
    }
};