#include <iostream>
#include <fstream>
#include "CSVReader.h"
#include <string>
#include "utils.h"

std::vector<std::string> CSVReader::readLine(std::string line)
{
    return split(line, ',');
}

void CSVReader::readFile(std::string fileName)
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

void CSVReader::display()
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

std::vector<std::vector<std::string>> CSVReader::getData()
{
    return data;
}