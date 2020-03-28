#pragma once

#include <string>
#include <vector>
#include "../model/model.h"

using namespace std;

void LoadPolicyLine(string line, Model model)
{
    if(line.size() == 0 || line[0] == '#')
        return;
    
    vector<string>token;
	int pre = 0;
	for (int i = 0; i < line.size(); ++i)
	{
		if (line[i] == ',')
		{
			string tmp = line.substr(pre, i - pre);
			token.push_back(tmp);
			pre = i + 1;
		}
	}
	if (pre < line.size())
	{
		string tmp = line.substr(pre, line.size()- pre);
		token.push_back(tmp);
	}
    string key = token[0];
    string sec = key.substr(0,2);

    //TODO: port "model[sec][key].Policy = append(model[sec][key].Policy, tokens[1:])"
}

//use virtual function to build a base class
class Adapter
{
    public:
        //TODO: use bool as error is temporarily
        // LoadPolicy loads all policy rules from the storage.
        virtual bool LoadPolicy(Model model) = 0;
        // SavePolicy saves all policy rules to the storage.
        virtual bool SavePolicy(Model model) = 0;

        // AddPolicy adds a policy rule to the storage.
        // This is part of the Auto-Save feature.
        virtual bool AddPolicy(string sec, string ptype, vector<string> rule) = 0;
        // RemovePolicy removes a policy rule from the storage.
        // This is part of the Auto-Save feature.
        virtual bool RemovePolicy(string sec, string ptype, vector<string> rule) = 0;
        // RemoveFilteredPolicy removes policy rules that match the filter from the storage.
        // This is part of the Auto-Save feature.
        //TODO:port "RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error"
};