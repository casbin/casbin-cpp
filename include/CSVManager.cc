#include <iostream>
#include <fstream>
#include "CSVManager.h"
#include <string>
#include "utils.h"

namespace casbin
{
std::vector<std::string> CSVManager::readLine(std::string line)
{
    return split(line, ',');
}

void CSVManager::readFile(std::string fileName)
{
    std::ifstream file(fileName, std::ios::out);
    if (!file.is_open())
    {
        std::cerr << "Error: Unable to open CSV file " << fileName << " for reading!" << std::endl;
        return;
    }

    std::string line;
    while (std::getline(file, line))
    {
        data.push_back(readLine(line));
    }

    file.close();
}

void CSVManager::writeFile(std::string fileName)
{
    std::ofstream fout;
    fout.open(fileName);

    std::string line = "";
    while (fout)
    {
        for (std::vector<std::string> vec : data)
        {
            line = join(vec, ',');
            fout << line << std::endl;
        }
    }

    // Close the File
    fout.close();
}

void CSVManager::display()
{
    for (std::vector<std::string> vec : data)
    {
        for (std::string ele : vec)
        {
            std::cout << ele << " ";
        }
        std::cout << std::endl;
    }
}

std::vector<std::vector<std::string>> CSVManager::getData()
{
    return data;
}
} // namespace casbin
