#ifndef REQUEST_H
#define REQUEST_H

#include <string>
#include <vector>
#include "../include/utils.h"
#include "Policy.h"

class Request
{
protected:
    std::string sub;
    std::string obj;
    std::string act;

public:
    Request(std::vector<std::string> arr)
    {
        sub = arr.at(0);
        obj = arr.at(1);
        act = arr.at(2);
    }
    Request(std::string line)
    {
        std::vector<std::string> arr = split(line, ',');
        sub = arr.at(0);
        obj = arr.at(1);
        act = arr.at(2);
    }
    friend bool matcher(Policy, Request);
};

#endif