#include <vector>
#include <string>

class Enforcer
{
    std::string model;
    std::string policy;

public:
    Enforcer(std::string m, std::string p)
    {
        model = m;
        policy = p;
    }

    std::vector<std::vector<std::string>> getPolicy();
    std::vector<std::vector<std::string>> getFilteredPolicy(int, std::string);
    std::vector<std::vector<std::string>> getNamedPolicy(std::string);
    std::vector<std::vector<std::string>> getFilteredNamedPolicy(std::string, int, std::string);
    bool hasPolicy(std::string, std::string, std::string);
    bool hasNamedPolicy(std::string, std::string, std::string, std::string);
};