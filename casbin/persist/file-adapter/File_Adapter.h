#ifndef CASBIN_CPP_PERSIST_FILE_ADAPTER_FILE_ADAPTER
#define CASBIN_CPP_PERSIST_FILE_ADAPTER_FILE_ADAPTER

#include "../Adapter.h"
#include "../../exception/CasbinAdapterException.h"
#include "../../exception/UnsupportedOperationException.h"
#include "../../util/arrayToString.h"

// Adapter is the file adapter for Casbin.
// It can load policy from file or save policy to file.
class FileAdapter : public Adapter {
    public:

        string  filePath;
        bool filtered;

        // NewAdapter is the constructor for Adapter.
        static FileAdapter* NewAdapter(string filePath) {
            FileAdapter adapter;
            adapter.filePath = filePath;
            adapter.filtered = false;
            return &adapter;
        }

        // LoadPolicy loads all policy rules from the storage.
        void LoadPolicy(Model model) {
            if(this->filePath == "") {
                throw CasbinAdapterException("Invalid file path, file path cannot be empty");
            }

            this->LoadPolicyFile(model, LoadPolicyLine);
        }

        // SavePolicy saves all policy rules to the storage.
        void SavePolicy(Model model) {
            if(this->filePath == "") {
                throw CasbinAdapterException("Invalid file path, file path cannot be empty");
            }

            string tmp;

            for(unordered_map <string, Assertion*> :: iterator it = model.M["p"].AMap.begin() ; it != model.M["p"].AMap.begin() ; it++){
                for(int i = 0 ; i < it->second->Policy.size() ; i++){
                    tmp += it->first + ", ";
                    tmp += arrayToString(it->second->Policy[i]);
                    tmp += "\n";
                }
            }

            for(unordered_map <string, Assertion*> :: iterator it = model.M["g"].AMap.begin() ; it != model.M["g"].AMap.begin() ; it++){
                for(int i = 0 ; i < it->second->Policy.size() ; i++){
                    tmp += it->first + ", ";
                    tmp += arrayToString(it->second->Policy[i]);
                    tmp += "\n";
                }
            }

            return this->SavePolicyFile(rtrim(tmp, "\n"));
        }

        void LoadPolicyFile(Model model, void (*handler)(string, Model)) {
            ifstream infile;
            try {
                infile.open(this->filePath);
            } catch (const ifstream::failure e) {
                throw IOException("Cannot open file.");
            }

            string line;
            while(getline(infile, line, '\n')){
                line = trim(line);
                handler(line, model);
            }

            infile.close();
        }

        void SavePolicyFile(string text) {
            ofstream outfile;
            outfile.open(this->filePath,ios::out);
            try {
                outfile.open(this->filePath,ios::out);
            } catch (const ifstream::failure e) {
                throw IOException("Cannot open file.");
            }

            outfile<<text;

            outfile.close();
        }

        // AddPolicy adds a policy rule to the storage.
        void AddPolicy(string sec, string ptype, vector<string> rule) {
            throw UnsupportedOperationException("not implemented");
        }

        // RemovePolicy removes a policy rule from the storage.
        void RemovePolicy(string sec, string ptype, vector<string> rule) {
            throw UnsupportedOperationException("not implemented");
        }

        // RemoveFilteredPolicy removes policy rules that match the filter from the storage.
        void RemoveFilteredPolicy(string sec, string ptype, int fieldIndex, vector<string> fieldValues) {
            throw UnsupportedOperationException("not implemented");
        }

        // IsFiltered returns true if the loaded policy has been filtered.
        bool IsFiltered() {
            return this->filtered;
        }
        
};

#endif