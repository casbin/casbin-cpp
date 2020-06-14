#pragma once

#include "pch.h"

#include "./batch_file_adapter.h"
#include "../../exception/unsupported_operation_exception.h"

// NewAdapter is the constructor for Adapter.
BatchFileAdapter* BatchFileAdapter :: NewAdapter(string file_path) {
    BatchFileAdapter* adapter = new BatchFileAdapter;
    adapter->file_path = file_path;
    adapter->filtered = false;
    return adapter;
}

void BatchFileAdapter :: AddPolicies(string sec, string p_type, vector<vector<string>> rules) {
    throw UnsupportedOperationException("not implemented hello");
}

void BatchFileAdapter :: RemovePolicies(string sec, string p_type, vector<vector<string>> rules) {
    throw UnsupportedOperationException("not implemented");
}