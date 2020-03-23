#include "file_adapter.h"

void FileAdapter::loadPolicy(Model* model) {
	if (filePath == "") return;
	
	ifstream file(filePath, ios::out);
	if (!file.is_open())
	{
		cerr << "Error: Unable to open policy file " << filePath << " for reading!" << endl;
		return;
	}

	string line;
	while (getline(file, line))
	{
		line = trim(line);
		loadPolicyLine(line, model);
	}

	file.close();
}

void FileAdapter::savePolicy(Model* model) {
	if (filePath == "") return;

	string buffer = "";

	AssertionMap* astm = model->model.find("p")->second;
	for (auto itr = astm->data.begin(); itr != astm->data.end(); itr++) {
		for (vector<string> arr : itr->second->policy) {
			buffer += itr->first + ", ";
			buffer += join(arr, ',');
			buffer += '\n';
		}
	}

	astm = model->model.find("g")->second;
	for (auto itr = astm->data.begin(); itr != astm->data.end(); itr++) {
		for (vector<string> arr : itr->second->policy) {
			buffer += itr->first + ", ";
			buffer += join(arr, ',');
			buffer += '\n';
		}
	}

	ofstream fout;
	fout.open(filePath);

	while (fout) {
		fout << buffer;
	}

	fout.close();
}

void FileAdapter::addPolicy(string sec, string ptype, vector<string> rule) {
	return;
}

void FileAdapter::removePolicy(string sec, string ptype, vector<string> rule) {
	return;
}