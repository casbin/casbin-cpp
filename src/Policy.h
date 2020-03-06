#ifndef POLICY_H
#define POLICY_H

#include <string>
#include <vector>
#include "../include/utils.h"
#include "Request.h"

class Policy
{
protected:
    std::string sub;
    std::string obj;
    std::string act;

public:
    Policy(std::vector<std::string> arr)
    {
        sub = arr.at(0);
        obj = arr.at(1);
        act = arr.at(2);
    }
    Policy(std::string line)
    {
        std::vector<std::string> arr = split(line, ',');
        sub = arr.at(0);
        obj = arr.at(1);
        act = arr.at(2);
    }
    bool isEqual(std::vector<std::string>);
    friend bool matcher(Policy, Request);
};

#endif