#ifndef CASBIN_CPP_PERSIST_FILE_ADAPTER_FILE_ADAPTER
#define CASBIN_CPP_PERSIST_FILE_ADAPTER_FILE_ADAPTER

#include "../adapter.h"
#include "../../exception/CasbinAdapterException.h"
#include "../../exception/UnsupportedOperationException.h"
#include "../../util/array_to_string.h"

// Adapter is the file adapter for Casbin.
// It can load policy from file or save policy to file.
class FileAdapter : public Adapter {
    public:

        string  file_path;
        bool filtered;

        // NewAdapter is the constructor for Adapter.
        static FileAdapter* NewAdapter(string file_path) {
            FileAdapter* adapter;
            adapter->file_path = file_path;
            adapter->filtered = false;
            return adapter;
        }

        // LoadPolicy loads all policy rules from the storage.
        void LoadPolicy(Model* model) {
            if (this->file_path == "") {
                throw CasbinAdapterException("Invalid file path, file path cannot be empty");
            }

            this->LoadPolicyFile(model, LoadPolicyLine);
        }

        // SavePolicy saves all policy rules to the storage.
        void SavePolicy(Model* model) {
            if (this->file_path == "") {
                throw CasbinAdapterException("Invalid file path, file path cannot be empty");
            }

            string tmp;

            for (unordered_map<string, Assertion*> :: iterator it = model->m["p"].assertion_map.begin() ; it != model->m["p"].assertion_map.begin() ; it++){
                for (int i = 0 ; i < it->second->policy.size() ; i++){
                    tmp += it->first + ", ";
                    tmp += ArrayToString(it->second->policy[i]);
                    tmp += "\n";
                }
            }

            for (unordered_map <string, Assertion*> :: iterator it = model->m["g"].assertion_map.begin() ; it != model->m["g"].assertion_map.begin() ; it++){
                for (int i = 0 ; i < it->second->policy.size() ; i++){
                    tmp += it->first + ", ";
                    tmp += ArrayToString(it->second->policy[i]);
                    tmp += "\n";
                }
            }

            return this->SavePolicyFile(RTrim(tmp, "\n"));
        }

        void LoadPolicyFile(Model* model, void (*handler)(string, Model*)) {
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

        void SavePolicyFile(string text) {
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
        void AddPolicy(string sec, string p_type, vector<string> rule) {
            throw UnsupportedOperationException("not implemented");
        }

        // RemovePolicy removes a policy rule from the storage.
        void RemovePolicy(string sec, string p_type, vector<string> rule) {
            throw UnsupportedOperationException("not implemented");
        }

        // RemoveFilteredPolicy removes policy rules that match the filter from the storage.
        void RemoveFilteredPolicy(string sec, string p_type, int field_index, vector<string> field_values) {
            throw UnsupportedOperationException("not implemented");
        }

        // IsFiltered returns true if the loaded policy has been filtered.
        bool IsFiltered() {
            return this->filtered;
        }
        
};

#endif