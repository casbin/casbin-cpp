#include "ConfReader.h"
#include <map>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include "utils.h"

namespace casbin
{

void ConfReader::readFile(std::string fileName)
{
    std::ifstream file(fileName, std::ios::out);
    if (!file.is_open())
    {
        std::cerr << "Error: Unable to open INI file " << fileName << " for reading!" << std::endl;
        return;
    }

    std::string line;
    std::string key;
    while (std::getline(file, line))
    {
        line = trim(line);
        if (line.length() == 0)
            continue;
        if (line.at(0) == '[' && line.at(line.length() - 1) == ']')
        {
            key.clear();
            key = line;
            key.erase(0, 1);
            key.erase(key.length() - 1, 1);
        }
        else
        {
            if (data.find(key) == data.end())
            {
                std::vector<std::string> temp;
                temp.push_back(line);
                data.insert(std::pair<std::string, std::vector<std::string>>(key, temp));
            }
            else
            {
                data.find(key)->second.push_back(line);
            }
        }
    }

    file.close();
}

void ConfReader::display()
{
    std::map<std::string, std::vector<std::string>>::iterator itr;
    for (itr = data.begin(); itr != data.end(); itr++)
    {
        std::cout << itr->first << std::endl;
        for (std::string ele : itr->second)
        {
            std::cout << ele << " ";
        }
        std::cout << std::endl;
    }
}

std::vector<std::string> ConfReader::getSections()
{
    std::vector<std::string> v;
    v.reserve(data.size());
    for (auto const &i : data)
        v.push_back(i.first);

    return v;
}

std::vector<std::string> ConfReader::getSectionData(std::string key)
{
    return data.find(key)->second;
}

} // namespace casbin