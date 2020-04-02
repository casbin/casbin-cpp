#include"file-adapter.h"
#include"adapter.h"
#include<fstream>
#include <sstream>
#include<iostream>
#include"exceptions.h"

using namespace std;

FileAdapter::FileAdapter(string filePath)
{
	this->filePath = filePath;
}

void FileAdapter::LoadPolicyLine(string line, Model& model)
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



	model.modelmap[sec][key].Policy.push_back(tokens);


}

void FileAdapter::LoadPolicyFile(Model& model, void (*handler)(string, Model&))
{
	ifstream csvInput;
	csvInput.open(filePath);
	string line;
	while (getline(csvInput, line))
	{
		handler(line, model);
	}
	csvInput.close();
}

void FileAdapter::LoadPolicy(Model& model)
{
	try {
		if (filePath == "")
			throw Exception("invalid file path, file path cannot be empty");
	}
	catch (Exception& e)
	{
		cout << e.what() << endl;
		return;
	}
	LoadPolicyFile(model, Adapter::LoadPolicyLine);
}


void FileAdapter::SavePolicy(Model &model)
{
	try {
		if (filePath == "")
			throw Exception("invalid file path, file path cannot be empty");
		return;
	}
	catch (exception& e)
	{
		cout << e.what() << endl;
	}

	string buffer;

	for (auto ast : model.modelmap["p"])
	{
		for (vector<string> rule : ast.second.Policy)
		{
			buffer += (ast.first + ", ");
			buffer += (Util::ArrayToString(rule));
			buffer += ("\n");
		}
	}

	for (auto ast : model.modelmap["g"])
	{
		for (vector<string> rule : ast.second.Policy)
		{
			buffer += (ast.first + ", ");
			buffer += (Util::ArrayToString(rule));
			buffer += ("\n");
		}
	}
	SavePolicyFile(buffer);
}

void FileAdapter::FileAdapter::SavePolicyFile(const string& text)
{
	ofstream outFile;
	try
	{
		outFile.open(filePath, ios::out);
		outFile << text;
	}
	catch (exception& e)
	{
		cout << e.what() << endl;
		outFile.close();
		return;
	}
	outFile.close();
}

//rules should be vectors like ["alice","data1","read"] , if the file doesn't exit, it will create a file(but not add a policy)
void FileAdapter::AddPolicy(string sec, string ptype, vector<string> rule)
{
	cout << "Add Policy:" << endl;
	bool exist = true;
	ifstream inFile(filePath);
	if (!inFile.good())
		exist = false;
	inFile.close();
	ofstream outFile;
	try
	{
		string buffer;
		if (!exist)
		{
			cout << "not exist" << endl;
			FILE* fp = NULL;
			fopen_s(&fp,filePath.data(), "w"); 
			fp == NULL;
			outFile.open(filePath, ios::out);
		}
		else
		{
			buffer += "\n";
			outFile.open(filePath, ios::app);
		}
		buffer += ptype + ", ";
		buffer += Util::ArrayToString(rule);
		cout <<"buffer:" << buffer << endl;
		outFile << buffer;
		cout << "buffer:" << buffer << endl;
	}
	catch (exception& e)
	{
		cout << e.what() << endl;
		outFile.close();
	}
	outFile.close();
}


void FileAdapter::AddPolicies(string sec, string ptype, vector<vector<string>> rules)
{
	throw Exception("not implemented");
}

void FileAdapter::RemovePolicy(string sec, string ptype, vector<string> rule)
{
	throw Exception("not implemented");
}

void FileAdapter::RemoveFilteredPolicy(string sec, string ptype, int fieldIndex, vector <string> fieldValues)
{
	throw Exception("not implemented");
}

