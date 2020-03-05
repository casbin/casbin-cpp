#include <string>
#include <vector>
#include <iostream>
#include <stdio.h>
#include <sstream>

std::string ltrim(std::string str, const std::string chars = "\t\n\v\f\r ")
{
    str.erase(0, str.find_first_not_of(chars));
    return str;
}

std::string rtrim(std::string str, const std::string chars = "\t\n\v\f\r ")
{
    str.erase(str.find_last_not_of(chars) + 1);
    return str;
}

std::string trim(std::string str, const std::string chars = "\t\n\v\f\r ")
{
    return ltrim(rtrim(str, chars), chars);
}

// std::vector<std::string> split(std::string line, char delimiter)
// {
//     std::vector<std::string> arr;
//     std::string temp = "";

//     for (auto i = 0; i < line.size(); i++)
//     {
//         if (line.at(i) == delimiter)
//         {
//             arr.push_back(temp);
//             temp.clear();
//         }
//         else
//             temp += line.at(i);
//     }
//     arr.push_back(temp);

//     return arr;
// }

std::vector<std::string> split(const std::string &p_pcstStr, char delim)
{
    std::vector<std::string> tokens;
    std::stringstream mySstream(p_pcstStr);
    std::string temp;

    while (getline(mySstream, temp, delim))
    {
        tokens.push_back(temp);
    }

    return tokens;
}