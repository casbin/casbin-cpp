#include "PolicyRule.h"
#include <vector>
#include <string>
#include "../include/utils.h"

void PolicyRule::addPolicy(std::vector<std::string> line)
{
    data.push_back(Policy(line));
}

std::vector<std::string> getPolicy(std::string line) {
    
}