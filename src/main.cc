#include "../adapters/json.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include "../include/utils.h"

int main()
{
    std::ifstream file("test.json", std::ios::out);
    if (!file.is_open())
    {
        std::cerr << "Error: Unable to open CSV file " << "test.json" << " for reading!" << std::endl;
        return 0;
    }

    std::string line;
    std::string data = "";
    while (std::getline(file, line))
    {
        line = trim(line);
        data += line;
    }

    file.close();
    auto j3 = nlohmann::json::parse(data);
    std::cout<<j3["romit"];

    return 0;
}