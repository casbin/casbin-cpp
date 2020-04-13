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

void FileAdapter::LoadPolicyFile(Model* model, void (*handler)(const string&, Model*))
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

void FileAdapter::LoadPolicy(Model* model)
{
	if (filePath == "")
		throw exception("invalid file path, file path cannot be empty");

	LoadPolicyFile(model, Adapter::LoadPolicyLine);
}


void FileAdapter::SavePolicy(Model* model)
{

	if (filePath == ""){
		throw exception("invalid file path, file path cannot be empty");
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

void FileAdapter::FileAdapter::SavePolicyFile(const string& text)
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
		cout << e.what() << endl;
		outFile.close();
	}

}

//rules should be vectors like ["alice","data1","read"] , if the file doesn't exit, it will create a file(but not add a policy)
void FileAdapter::AddPolicy(const string& sec, const string& ptype, const vector<string>& rule)
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
		cout << e.what() << endl;
		outFile.close();
	}
}


void FileAdapter::RemovePolicy(const string& sec, const string& ptype, const vector<string>& rule)
{
	throw exception("not implemented");
}

void FileAdapter::RemoveFilteredPolicy(const string& sec, const string& ptype, const int& fieldIndex, const vector <string>& fieldValues)
{
	throw exception("not implemented");
}
