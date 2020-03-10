#pragma once

#ifndef OPERATOR_H
#define OPERATOR_H

#endif

#include <string>

using namespace std;

class Operator {
public:
    string symbol;
    virtual string operate(string, string) = 0;
    virtual bool operate(bool, bool) = 0;
};

class AND : public Operator
{
public:
    AND()
    {
        symbol = "&&";
    }
    string operate(string, string);
    bool operate(bool, bool);
};

class OR : public Operator
{
public:
    OR()
    {
        symbol = "||";
    }
    string operate(string, string);
    bool operate(bool, bool);
};

class EQUALS : public Operator
{
public:
    EQUALS()
    {
        symbol = "==";
    }
    string operate(string, string);
    bool operate(bool, bool);
};