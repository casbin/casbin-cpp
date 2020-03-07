#include <map>
#include <string>
#include <vector>
#include "../../include/ConfReader.h"

using namespace std;

class Model : ConfReader
{
    map<string, string> sectionNameMap = {
        {"r", "request_definition"},
        {"p", "policy_definition"},
        {"g", "role_definition"},
        {"e", "policy_effect"},
        {"m", "matchers"}};

    vector<string> requiredSections{"r", "p", "g", "e", "m"};

protected:
    bool isValid();

public:
    void readModel(string);
};

bool Model::isValid()
{
    vector<string> arr = getSections();
    for (auto const &i : requiredSections)
    {
        map<string, string>::iterator temp = sectionNameMap.find(i);
        vector<string>::iterator it = find(arr.begin(), arr.end(), temp->second);
        if (it == arr.end())
            return false;
    }

    return true;
}

void Model::readModel(string fileName)
{
    readFile(fileName);
    if (!isValid())
        return;
}