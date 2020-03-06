#include "Policy.h"

bool Policy::isEqual(std::vector<std::string> line) {
    bool response = true;
    if(line.at(0) != sub) response = false;
    if(line.at(0) != obj) response = false;
    if(line.at(0) != act) response = false;

    return response;
}