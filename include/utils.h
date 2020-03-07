#include <string>
#include <vector>
#include <iostream>
#include <stdio.h>
#include <sstream>

inline std::string ltrim(std::string str, const std::string chars = "\t\n\v\f\r ")
{
    str.erase(0, str.find_first_not_of(chars));
    return str;
}

inline std::string rtrim(std::string str, const std::string chars = "\t\n\v\f\r ")
{
    str.erase(str.find_last_not_of(chars) + 1);
    return str;
}

inline std::string trim(std::string str, const std::string chars = "\t\n\v\f\r ")
{
    return ltrim(rtrim(str, chars), chars);
}

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

std::string join(std::vector<std::string> arr, char delim)
{
    std::string temp = "";
    for (std::string ele : arr)
    {
        if (temp.size() != 0)
        {
            temp += delim;
            temp += ele;
        }
        else
            temp += ele;
    }

    return temp;
}