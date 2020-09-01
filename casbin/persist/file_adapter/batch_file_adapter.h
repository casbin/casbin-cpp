#ifndef CASBIN_CPP_PERSIST_FILE_ADAPTER_BATCH_FILE_ADAPTER
#define CASBIN_CPP_PERSIST_FILE_ADAPTER_BATCH_FILE_ADAPTER

#include "./file_adapter.h"
#include "../batch_adapter.h"

class BatchFileAdapter: public BatchAdapter, public FileAdapter {
    public:

        // NewAdapter is the constructor for Adapter.
        BatchFileAdapter(string file_path);

        void AddPolicies(string sec, string p_type, vector<vector<string>> rules);

        void RemovePolicies(string sec, string p_type, vector<vector<string>> rules);
};

#endif