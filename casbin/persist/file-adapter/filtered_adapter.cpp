#pragma once

#include "pch.h"

#include <fstream>

#include "./filtered_adapter.h"
#include "../../exception/io_exception.h"
#include "../../exception/casbin_adapter_exception.h"

using namespace std;

bool FilteredAdapter :: filterLine(string line, Filter* filter) {
    if (filter == NULL)
        return false;

    vector<string> p = Split(line, ",");
    if(p.size() == 0)
        return true;

    vector<string> filter_slice;
    string str = Trim(p[0]);
    if (str=="p")
        filter_slice = filter->P;
    else if (str=="g")
        filter_slice = filter->G;

    return filterWords(p, filter_slice);
}

bool FilteredAdapter :: filterWords(vector<string> line, vector<string> filter) {
    if (line.size() < filter.size()+1)
        return true;

    bool skip_line;
    for (int i = 0 ; i < filter.size() ; i++) {
        if (filter[i].length()>0 && Trim(filter[i]) != Trim(line[i+1])) {
            skip_line = true;
            break;
        }
    }

    return skip_line;
}

void FilteredAdapter :: loadFilteredPolicyFile(Model* model, Filter* filter, void (*handler)(string, Model*)) {
    ifstream out_file;
    try {
        out_file.open(this->file_path);
    } catch (const ifstream::failure e) {
        throw IOException("Cannot open file.");
    }

    string line;
    while (getline(out_file, line, '\n')) {
        line = Trim(line);
        if (filterLine(line, filter)) {
            continue;
        }

        handler(line, model);
    }

    out_file.close();
}

// NewFilteredAdapter is the constructor for FilteredAdapter.
FilteredAdapter* FilteredAdapter :: NewFilteredAdapter(string file_path) {
    FilteredAdapter* a = new FilteredAdapter;
    a->filtered = true;
    a->file_path = file_path;
    return a;
}

// LoadPolicy loads all policy rules from the storage.
void FilteredAdapter :: LoadPolicy(Model* model) {
    this->filtered = false;
    this->FileAdapter::LoadPolicy(model);
}

// LoadFilteredPolicy loads only policy rules that match the filter.
void FilteredAdapter :: LoadFilteredPolicy(Model* model, Filter* filter) {
    if (filter == NULL) {
        this->LoadPolicy(model);
    }

    if (this->file_path == "") {
        throw CasbinAdapterException("Invalid file path, file path cannot be empty");
    }

    this->loadFilteredPolicyFile(model, filter, LoadPolicyLine);
    this->filtered = true;
}

// IsFiltered returns true if the loaded policy has been filtered.
bool FilteredAdapter :: IsFiltered() {
    return this->filtered;
}

// SavePolicy saves all policy rules to the storage.
void FilteredAdapter :: SavePolicy(Model* model) {
    if (this->filtered) {
        throw CasbinAdapterException("Cannot save a filtered policy");
    }
    this->SavePolicy(model);
}