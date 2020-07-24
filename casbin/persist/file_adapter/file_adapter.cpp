#pragma once

#include "pch.h"

#include <fstream>

#include "./file_adapter.h"
#include "../../util/util.h"
#include "../../exception/io_exception.h"
#include "../../exception/unsupported_operation_exception.h"
#include "../../exception/casbin_adapter_exception.h"

// NewAdapter is the constructor for Adapter.
FileAdapter :: FileAdapter(string file_path) {
    this->file_path = file_path;
    this->filtered = false;
}

// LoadPolicy loads all policy rules from the storage.
void FileAdapter :: LoadPolicy(Model* model) {
    if (this->file_path == "")
        throw CasbinAdapterException("Invalid file path, file path cannot be empty");

    this->LoadPolicyFile(model, LoadPolicyLine);
}

// SavePolicy saves all policy rules to the storage.
void FileAdapter :: SavePolicy(Model* model) {
    if (this->file_path == "") {
        throw CasbinAdapterException("Invalid file path, file path cannot be empty");
    }

    string tmp;

    for (unordered_map<string, shared_ptr<Assertion>> :: iterator it = model->m["p"].assertion_map.begin() ; it != model->m["p"].assertion_map.begin() ; it++){
        for (int i = 0 ; i < it->second->policy.size() ; i++){
            tmp += it->first + ", ";
            tmp += ArrayToString(it->second->policy[i]);
            tmp += "\n";
        }
    }

    for (unordered_map <string, shared_ptr<Assertion>> :: iterator it = model->m["g"].assertion_map.begin() ; it != model->m["g"].assertion_map.begin() ; it++){
        for (int i = 0 ; i < it->second->policy.size() ; i++){
            tmp += it->first + ", ";
            tmp += ArrayToString(it->second->policy[i]);
            tmp += "\n";
        }
    }

    return this->SavePolicyFile(RTrim(tmp, "\n"));
}

void FileAdapter :: LoadPolicyFile(Model* model, void (*handler)(string, Model*)) {
    ifstream in_file;
    try {
        in_file.open(this->file_path);
    } catch (const ifstream::failure e) {
        throw IOException("Cannot open file.");
    }

    string line;
    while(getline(in_file, line, '\n')){
        line = Trim(line);
        handler(line, model);
    }

    in_file.close();
}

void FileAdapter :: SavePolicyFile(string text) {
    ofstream out_file;
    out_file.open(this->file_path,ios::out);
    try {
        out_file.open(this->file_path,ios::out);
    } catch (const ifstream::failure e) {
        throw IOException("Cannot open file.");
    }

    out_file<<text;

    out_file.close();
}

// AddPolicy adds a policy rule to the storage.
void FileAdapter :: AddPolicy(string sec, string p_type, vector<string> rule) {
    throw UnsupportedOperationException("not implemented");
}

// RemovePolicy removes a policy rule from the storage.
void FileAdapter :: RemovePolicy(string sec, string p_type, vector<string> rule) {
    throw UnsupportedOperationException("not implemented");
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
void FileAdapter :: RemoveFilteredPolicy(string sec, string p_type, int field_index, vector<string> field_values) {
    throw UnsupportedOperationException("not implemented");
}

// IsFiltered returns true if the loaded policy has been filtered.
bool FileAdapter :: IsFiltered() {
    return this->filtered;
}