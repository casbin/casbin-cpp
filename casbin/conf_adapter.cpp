#include "pch.h"
#include "conf_adapter.h"

void ConfAdapter::readFile(string fileName)
{
    ifstream file(fileName, ios::out);
    if (!file.is_open())
    {
        cerr << "Error: Unable to open INI file " << fileName << " for reading!" << endl;
        return;
    }

    string line;
    string key;
    smatch m;
    while (getline(file, line))
    {
        line = regex_replace(line, std::regex("[#;].*"), ""); // Remove comments from config
        line = trim(line);
        if (line.length() == 0)
            continue;
        if (regex_search(line, m, regex("\\[.*\\]"))) // Check for section
        {
            key.clear();
            key = m.str().substr(1, m.str().length() - 2);
        }
        else
        {
            if (data.find(key) == data.end())
            {
                vector<string> temp;
                temp.push_back(line);
                data.insert(pair<string, vector<string>>(key, temp));
            }
            else
            {
                data.find(key)->second.push_back(line);
            }
        }
    }

    file.close();
}

void ConfAdapter::display()
{
    map<string, vector<string>>::iterator itr;
    for (itr = data.begin(); itr != data.end(); itr++)
    {
        printf("%s \n", itr->first.c_str());
        for (string ele : itr->second)
        {
            printf("%s ", ele.c_str());
        }
        printf("\n");
    }
}

vector<string> ConfAdapter::getSections()
{
    vector<string> v;
    v.reserve(data.size());
    for (auto const& i : data)
        v.push_back(i.first);

    return v;
}

vector<string> ConfAdapter::getSectionData(string key)
{
    return data.find(key)->second;
}