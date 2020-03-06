#include<map>
#include<vector>
#include<string>

class ConfReader {
    const std::string rd = "request_definition";
    const std::string pd = "policy_definition";
    const std::string pe = "policy_effect";
    const std::string m = "matchers";
    const std::string rld = "role_definition";

    std::map<std::string, std::string> data;
public:
    std::string returnContext(std::string);
    void readFile(std::string);
    void display();
};