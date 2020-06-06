#ifndef CASBIN_CPP_PERSIST_FILE_ADAPTER_BATCH_FILE_ADAPTER
#define CASBIN_CPP_PERSIST_FILE_ADAPTER_BATCH_FILE_ADAPTER

#include "./file_adapter.h"
#include "../batch_adapter.h"

class BatchFileAdapter: public BatchAdapter, public FileAdapter {
    public:

        // NewAdapter is the constructor for Adapter.
        static BatchFileAdapter* NewAdapter(string file_path) {
            BatchFileAdapter* adapter = new BatchFileAdapter;
            adapter->file_path = file_path;
            adapter->filtered = false;
            return adapter;
        }

        void AddPolicies(string sec, string p_type, vector<vector<string>> rules) {
            throw UnsupportedOperationException("not implemented hello");
        }

        void RemovePolicies(string sec, string p_type, vector<vector<string>> rules) {
            throw UnsupportedOperationException("not implemented");
        }
};

#endif