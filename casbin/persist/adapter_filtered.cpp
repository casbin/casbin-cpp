#include "adapter_filtered.h"
#include "./file-adapter/file-adapter.h"
#include <fstream>
#include<iostream>

Filter::Filter() {

}

Filter::Filter(const vector<string>& p, const vector<string>& g) {
	P = p;
	G = g;
}

Filteredadapter* Filteredadapter::NewFilteredAdapter(const string& filePath) {
	Filteredadapter* fa = new Filteredadapter();
	fa->filtered = true;
	fa->adapter = new FileAdapter(filePath);
	return fa;
}

Error Filteredadapter::LoadPolicy(Model* model) {
	filtered = false;
	return adapter->LoadPolicy(model);
}

Error Filteredadapter::LoadFilteredPolicy(Model* model, Filter* filter) {
	if (filter == NULL){
		return LoadPolicy(model);
	}
	if (adapter->filePath == "") {
		return Error("invalid file path, file path cannot be empty");
	}

	Error err = LoadFilteredPolicyFile(model, filter, Adapter::LoadPolicyLine);
		if (err.IsNull()){
			filtered = true;
		}
		return err;
}

Error Filteredadapter::LoadFilteredPolicyFile(Model* model, Filter* filter, void(*handler)(const string&, Model*)) {
	ifstream csvInput;
	csvInput.open(adapter->filePath);
	string line;
	while (getline(csvInput, line))
	{
		line = Util::Trim(line, " ");

		if (filterLine(line, filter)) {
			continue;
		}

		handler(line, model);
	}
	csvInput.close();
	return Error();
}

bool Filteredadapter::IsFiltered() {
	return filtered;
}

Error Filteredadapter::SavePolicy(Model* model) {
	if (filtered){
		return Error("cannot save a filtered policy");
	}
	return adapter->SavePolicy(model);
}

bool Filteredadapter::filterLine(const string& line, Filter* filter) {
	if (filter == NULL){
		return false;
	}
	vector<string> p = Util::Split(line, ",");
	if (p.size() == 0 ){
		return true;
	}
	vector<string> filterSlice;
	string choose = Util::Trim(p[0], " ");
	if (choose == "p") {
		filterSlice = filter->P;
	}
	else if (choose == "g") {
		filterSlice = filter->G;
	}
	return filterWords(p, filterSlice);
}

bool Filteredadapter::filterWords(const vector<string>& line, const vector<string>& filter) {
	if (line.size() < (filter.size() + 1) ) {
		return true;
	}
	bool skipLine = false;
	for(int i=0;i<filter.size();i++){
		string v = filter[i];
		if (v.size() > 0 && Util::Trim(v," ") != Util::Trim(line[i + 1]," ") ) {
			skipLine = true;
			break;
		}
	}
	return skipLine;
}

Error Filteredadapter::AddPolicy(const string& sec, const string& ptype, const vector<string>& rule)
{
	return Error("not implemented");
}

Error Filteredadapter::RemovePolicy(const string& sec, const string& ptype, const vector<string>& rule)
{
	return Error("not implemented");
}

Error Filteredadapter::RemoveFilteredPolicy(const string& sec, const string& ptype, const int& fieldIndex, const vector <string>& fieldValues)
{
	return Error("not implemented");
}