#include "../include/CSVManager.h"
#include <vector>
#include <string>
#include <algorithm>
#include "Enforcer.h"

std::vector<std::vector<std::string>> Enforcer::getPolicy()
{
    CSVManager manager;
    manager.readFile(policy);
    return manager.getData();
}

std::vector<std::vector<std::string>> Enforcer::getFilteredPolicy(int index, std::string filter)
{
    CSVManager manager;
    manager.readFile(policy);
    std::vector<std::vector<std::string>> temp = manager.getData();
    std::vector<std::vector<std::string>> result = manager.getData();
    int i = 0;

    for (std::vector<std::string> ele : temp)
    {
        if (ele.at(index + 1) != filter)
            result.erase(result.begin() + i);
        i++;
    }
}

std::vector<std::vector<std::string>> Enforcer::getNamedPolicy(std::string filter)
{
    CSVManager manager;
    manager.readFile(policy);
    std::vector<std::vector<std::string>> temp = manager.getData();
    std::vector<std::vector<std::string>> result = manager.getData();
    int i = 0;

    for (std::vector<std::string> ele : temp)
    {
        if (ele.at(0) != filter)
            result.erase(result.begin() + i);
        i++;
    }

    return result;
}

std::vector<std::vector<std::string>> Enforcer::getFilteredNamedPolicy(std::string policy, int index, std::string filter)
{
    CSVManager manager;
    manager.readFile(policy);
    std::vector<std::vector<std::string>> temp = manager.getData();
    std::vector<std::vector<std::string>> result = manager.getData();
    int i = 0;

    for (std::vector<std::string> ele : temp)
    {
        if (ele.at(0) != policy)
            result.erase(result.begin() + i);
        else if (ele.at(index + 1) != filter)
            result.erase(result.begin() + i);
        i++;
    }

    return result;
}

bool Enforcer::hasPolicy(std::string sub, std::string obj, std::string act)
{
    CSVManager manager;
    manager.readFile(policy);
    std::vector<std::vector<std::string>> temp = manager.getData();
    std::vector<std::string> tempArr;

    tempArr.push_back(sub);
    tempArr.push_back(obj);
    tempArr.push_back(act);

    for (std::vector<std::string> ele : temp)
        if (std::equal(tempArr.begin(), tempArr.end(), ele.begin() + 1, ele.end()))
            return true;

    return false;
}

bool Enforcer::hasNamedPolicy(std::string p, std::string sub, std::string obj, std::string act)
{
    CSVManager manager;
    manager.readFile(policy);
    std::vector<std::vector<std::string>> temp = manager.getData();
    std::vector<std::string> tempArr;

    tempArr.push_back(p);
    tempArr.push_back(sub);
    tempArr.push_back(obj);
    tempArr.push_back(act);

    for (std::vector<std::string> ele : temp)
        if (ele == tempArr)
            return true;

    return false;
}

