#include "ConfReader.h"
#include <map>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include "utils.h"

std::string ConfReader::returnContext(std::string line)
{
    line.erase(0, 1);
    line.erase(line.size() - 1, 1);
    // std::cout<<line;
    if (line == rd)
        return rd;
    if (line == pd)
        return pd;
    if (line == pe)
        return pe;
    if (line == m)
        return m;
    if (line == rld)
        return rld;
    return "";
}

void ConfReader::readFile(std::string fileName)
{
    std::ifstream file(fileName, std::ios::out);
    if (!file.is_open())
    {
        std::cerr << "Error: Unable to open CSV file " << fileName << " for reading!" << std::endl;
        return;
    }

    std::string line;
    std::string context;
    while (std::getline(file, line))
    {
        line = trim(line);
        if (line.size() == 0)
            continue;
        if (returnContext(line).size() != 0)
            context = returnContext(line);
        else
        {
            std::vector<std::string> arr;
            if (context == rld)
            {
                
            }
            else if (context != m && context != pe)
            {
                arr = split(line, '=');
                data.insert(std::pair<std::string, std::string>(context, arr[1]));
            }
            else
            {
                data.insert(std::pair<std::string, std::string>(context, line));
            }
        }
    }

    file.close();
}

void ConfReader::display()
{
    std::map<std::string, std::string>::iterator itr;
    for (itr = data.begin(); itr != data.end(); itr++)
    {
        std::cout << '\t' << itr->first
                  << '\t' << itr->second << '\n';
    }
}