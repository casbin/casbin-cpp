#include"file-adapter.h"
#include"../adapter.h"
#include<fstream>
#include <sstream>
#include<iostream>
#include"../../errors/exceptions.h"

using namespace std;

FileAdapter::FileAdapter(const string& filePath)
{
	this->filePath = filePath;
}


FileAdapter* FileAdapter::newFileAdapter(const string& filePath)
{
	FileAdapter* fa = new FileAdapter(filePath);
	return fa;
}

void FileAdapter::LoadPolicyLine(const string& line, Model* model)
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

Error FileAdapter::LoadPolicyFile(Model* model, void (*handler)(const string&, Model*))
{
	ifstream csvInput;
	csvInput.open(filePath);
	string line;
	while (getline(csvInput, line))
	{
		handler(line, model);
	}
	csvInput.close();
	return Error();
}

Error FileAdapter::LoadPolicy(Model* model)
{
	if (filePath == "")
		return Error("invalid file path, file path cannot be empty");

	return LoadPolicyFile(model, Adapter::LoadPolicyLine);
}


Error FileAdapter::SavePolicy(Model* model)
{

	if (filePath == ""){
		return Error("invalid file path, file path cannot be empty");
	}

	string buffer;

	for (auto ast : model->modelmap["p"])
	{
		for (vector<string> rule : ast.second.Policy)
		{
			buffer += (ast.first + ", ");
			buffer += (Util::ArrayToString(rule));
			buffer += ("\n");
		}
	}

	for (auto ast : model->modelmap["g"])
	{
		for (vector<string> rule : ast.second.Policy)
		{
			buffer += (ast.first + ", ");
			buffer += (Util::ArrayToString(rule));
			buffer += ("\n");
		}
	}

	return SavePolicyFile(buffer);
}

Error FileAdapter::FileAdapter::SavePolicyFile(const string& text)
{
	ofstream outFile;
	try
	{
		outFile.open(filePath, ios::out);
		outFile << text;
		outFile.close();
	}
	catch (exception& e)
	{
		string s = e.what();
		Error err = Error(s);
		outFile.close();
		return err;
	}
	return Error();
}

//rules should be vectors like ["alice","data1","read"] , if the file doesn't exit, it will create a file(but not add a policy)
Error FileAdapter::AddPolicy(const string& sec, const string& ptype, const vector<string>& rule)
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
		outFile.close();
	}
	catch (exception& e)
	{
		string s =e.what();
		Error err = Error(s);
		outFile.close();
		return err;
	}
	return Error();
}


Error FileAdapter::RemovePolicy(const string& sec, const string& ptype, const vector<string>& rule)
{
	return Error("not implemented");
}

Error FileAdapter::RemoveFilteredPolicy(const string& sec, const string& ptype, const int& fieldIndex, const vector <string>& fieldValues)
{
	return Error("not implemented");
}
