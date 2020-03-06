#include <map>
#include <vector>
#include <string>
#include "../include/CSVManager.h"

class PolicyHandler : CSVManager
{
    std::map<std::string, std::vector<std::string>> policy;

public:
    void readPolicy(std::string);
};