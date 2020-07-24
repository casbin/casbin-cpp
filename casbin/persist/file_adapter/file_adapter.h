#ifndef CASBIN_CPP_PERSIST_FILE_ADAPTER_FILE_ADAPTER
#define CASBIN_CPP_PERSIST_FILE_ADAPTER_FILE_ADAPTER

#include "../adapter.h"

// Adapter is the file adapter for Casbin.
// It can load policy from file or save policy to file.
class FileAdapter : virtual public Adapter {
    public:

        // NewAdapter is the constructor for Adapter.
        FileAdapter(string file_path);

        // LoadPolicy loads all policy rules from the storage.
        void LoadPolicy(Model* model);

        // SavePolicy saves all policy rules to the storage.
        void SavePolicy(Model* model);

        void LoadPolicyFile(Model* model, void (*handler)(string, Model*));

        void SavePolicyFile(string text);

        // AddPolicy adds a policy rule to the storage.
        void AddPolicy(string sec, string p_type, vector<string> rule);

        // RemovePolicy removes a policy rule from the storage.
        void RemovePolicy(string sec, string p_type, vector<string> rule);

        // RemoveFilteredPolicy removes policy rules that match the filter from the storage.
        void RemoveFilteredPolicy(string sec, string p_type, int field_index, vector<string> field_values);

        // IsFiltered returns true if the loaded policy has been filtered.
        bool IsFiltered();
};

#endif