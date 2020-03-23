#pragma once

#include <exception>

using namespace std;

struct ERR_NAME_NOT_FOUND : public exception {
    const char* what() const throw () {
        return "error: name does not exist";
    }
};

struct ERR_DOMAIN_PARAMETER : public exception {
    const char* what() const throw () {
        return "error: domain should be 1 parameter";
    }
};

struct ERR_NAMES12_NOT_FOUND : public exception {
    const char* what() const throw () {
        return "error: name1 or name2 does not exist";
    }
};