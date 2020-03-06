#include <vector>
#include "Policy.h"

class PolicyRule
{
public:
    std::vector<Policy> data;
    void addPolicy(std::vector<std::string>);
    std::vector<std::string> getPolicy(std::string);
};