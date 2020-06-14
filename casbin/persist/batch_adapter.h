#ifndef CASBIN_CPP_PERSIST_BATCH_ADAPTER
#define CASBIN_CPP_PERSIST_BATCH_ADAPTER

#include "./adapter.h"

class BatchAdapter: virtual public Adapter {
    public:

        // AddPolicies adds policy rules to the storage.
        // This is part of the Auto-Save feature.
        virtual void AddPolicies(string sec, string p_type, vector<vector<string>> rules) = 0;
        // RemovePolicies removes policy rules from the storage.
        // This is part of the Auto-Save feature.
        virtual void RemovePolicies(string sec, string p_type, vector<vector<string>> rules) = 0;
};

#endif