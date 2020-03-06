#include <map>
#include <vector>
#include <string>
#include "PolicyHandler.h"
#include "../include/CSVManager.h"
#include "../include/utils.h"

void PolicyHandler::readPolicy(std::string fileName)
    {
        readFile(fileName);
        std::vector<std::vector<std::string>> temp = getData();
        for (std::vector<std::string> ele : temp)
        {
            if (policy.find(ele.at(0)) == policy.end())
            {
                ele.erase(ele.begin());
                std::vector<std::string> tempVec;
                tempVec.push_back(join(ele, ','));
                policy.insert(std::pair<std::string, std::vector<std::string>>(ele.at(0), tempVec));
            }
            else
            {
                std::map<std::string, std::vector<std::string>>::iterator itr = policy.find(ele.at(0));
                itr->second.push_back(join(ele, ','));
            }
        }
    }