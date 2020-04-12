#include"adapter.h"
#include<iostream>
#include<fstream>
using namespace std;

void Adapter::LoadPolicyLine(const string& line, Model* model)
{

	if (line == "" || Util::HasPrefix(line, "#")) {
		return;
	}


	vector<string> tokens = Util::Split(line, ",");


	for (int i = 0; i < tokens.size(); i++)
	{
		tokens[i] = Util::Trim(tokens[i], " ");
	}

	string key = tokens[0];
	string sec = key;
	vector<string>::iterator itBegin = tokens.begin();
	tokens.erase(itBegin, itBegin + 1);

	model->modelmap[sec][key].Policy.push_back(tokens);


}