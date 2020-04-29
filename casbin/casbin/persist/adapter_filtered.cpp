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

Filteredadapter::Filteredadapter() {

}

Filteredadapter::Filteredadapter(Filteredadapter& fa) {
	this->adapter = move(fa.adapter);
	this->filtered = fa.filtered;
	this->filePath = fa.filePath;
}

Filteredadapter::Filteredadapter(const string& filePath) {
	filtered = true;
	adapter = unique_ptr<Adapter>(new FileAdapter(filePath));
}

Filteredadapter* Filteredadapter::NewFilteredAdapter(const string& filePath) {
	Filteredadapter* fa = new Filteredadapter();
	fa->filtered = true;
	fa->adapter = unique_ptr<Adapter>(new FileAdapter(filePath));
	return fa;
}

void Filteredadapter::LoadPolicy(Model* model) {
	filtered = false;
	adapter->LoadPolicy(model);
}

void Filteredadapter::LoadFilteredPolicy(Model* model, Filter* filter) {
	if (filter == NULL){
		return LoadPolicy(model);
	}
	if (adapter->filePath == "") {
		throw exception("invalid file path, file path cannot be empty");
	}

	try {
		LoadFilteredPolicyFile(model, filter, Adapter::LoadPolicyLine);
	}
	catch (exception& e) {
		filtered = true;
		throw e;
	}
}

void Filteredadapter::LoadFilteredPolicyFile(Model* model, Filter* filter, void(*handler)(const string&, Model*)) {
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
}

bool Filteredadapter::IsFiltered() {
	return filtered;
}

void Filteredadapter::SavePolicy(Model* model) {
	if (filtered){
		throw exception("cannot save a filtered policy");
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

void Filteredadapter::AddPolicy(const string& sec, const string& ptype, const vector<string>& rule)
{
	throw exception("not implemented");
}

void Filteredadapter::RemovePolicy(const string& sec, const string& ptype, const vector<string>& rule)
{
	throw exception("not implemented");
}

void Filteredadapter::RemoveFilteredPolicy(const string& sec, const string& ptype, const int& fieldIndex, const vector <string>& fieldValues)
{
	throw exception("not implemented");
}