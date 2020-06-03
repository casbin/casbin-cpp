#ifndef CASBIN_CPP_PERSIST_FILE_ADAPTER_FILTERED_ADAPTER
#define CASBIN_CPP_PERSIST_FILE_ADAPTER_FILTERED_ADAPTER

#include "file_adapter.h"
#include "../adapter.h"

// Filter defines the filtering rules for a FilteredAdapter's policy. Empty values
// are ignored, but all others must match the filter.
class Filter{
    public:
        vector<string> P;
        vector<string> G;
};

class FilteredAdapter : public FileAdapter {
    public:

        // NewFilteredAdapter is the constructor for FilteredAdapter.
        static FilteredAdapter* NewFilteredAdapter(string file_path) {
            FilteredAdapter* a;
            a->filtered = true;
            a->file_path = file_path;
            return a;
        }

        static bool filterLine(string line, Filter* filter) {
            if (filter == NULL) {
                return false;
            }

            vector<string> p = Split(line, ",");
            if(p.size() == 0) {
                return true;
            }

            vector<string> filter_slice;
            string str = Trim(p[0]);
            if (str=="p") {
                filter_slice = filter->P;
            } else if (str=="g") {
                filter_slice = filter->G;
            }

            return filterWords(p, filter_slice);
        }

        static bool filterWords(vector<string> line, vector<string> filter) {
            if (line.size() < filter.size()+1) {
                return true;
            }

            bool skip_line;
            for (int i = 0 ; i < filter.size() ; i++) {
                if (filter[i].length()>0 && Trim(filter[i]) != Trim(line[i+1])) {
                    skip_line = true;
                    break;
                }
            }

            return skip_line;
        }

        // LoadPolicy loads all policy rules from the storage.
        void LoadPolicy(Model* model) {
            this->filtered = false;
            this->LoadPolicy(model);
        }

        // LoadFilteredPolicy loads only policy rules that match the filter.
        void LoadFilteredPolicy(Model* model, Filter* filter) {
            if (filter == NULL) {
                this->LoadPolicy(model);
            }

            if (this->file_path == "") {
                throw CasbinAdapterException("Invalid file path, file path cannot be empty");
            }

            this->LoadFilteredPolicyFile(model, filter, LoadPolicyLine);
            this->filtered = true;
        }

        void LoadFilteredPolicyFile(Model* model, Filter* filter, void (*handler)(string, Model*)) {
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

        // IsFiltered returns true if the loaded policy has been filtered.
        bool IsFiltered() {
            return this->filtered;
        }

        // SavePolicy saves all policy rules to the storage.
        void SavePolicy(Model* model) {
            if (this->filtered) {
                throw CasbinAdapterException("Cannot save a filtered policy");
            }
            this->SavePolicy(model);
        }
};

#endif