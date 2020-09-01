#pragma once

#include "pch.h"

#include <fstream>

#include "./filtered_file_adapter.h"
#include "../../exception/io_exception.h"
#include "../../exception/casbin_adapter_exception.h"
#include "../../util/util.h"

using namespace std;

bool FilteredFileAdapter :: filterLine(string line, Filter* filter) {
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

bool FilteredFileAdapter :: filterWords(vector<string> line, vector<string> filter) {
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

void FilteredFileAdapter :: loadFilteredPolicyFile(Model* model, Filter* filter, void (*handler)(string, Model*)) {
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
FilteredFileAdapter :: FilteredFileAdapter(string file_path): FileAdapter(file_path) {
    this->filtered = true;
}

// LoadPolicy loads all policy rules from the storage.
void FilteredFileAdapter :: LoadPolicy(Model* model) {
    this->filtered = false;
    this->FileAdapter::LoadPolicy(model);
}

// LoadFilteredPolicy loads only policy rules that match the filter.
void FilteredFileAdapter :: LoadFilteredPolicy(Model* model, Filter* filter) {
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
bool FilteredFileAdapter :: IsFiltered() {
    return this->filtered;
}

// SavePolicy saves all policy rules to the storage.
void FilteredFileAdapter :: SavePolicy(Model* model) {
    if (this->filtered) {
        throw CasbinAdapterException("Cannot save a filtered policy");
    }
    this->SavePolicy(model);
}