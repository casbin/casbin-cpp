#pragma once
#include <string>
#include <exception>

using namespace std;


class Exception :public exception {
    string error_info;
public:
    Exception(string s);
    const char* what() const throw ();
};