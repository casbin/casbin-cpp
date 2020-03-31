#ifndef CASBIN_CPP_PERSIST_FILE_ADAPTER_FILTERED_ADAPTER
#define CASBIN_CPP_PERSIST_FILE_ADAPTER_FILTERED_ADAPTER

#include "File_Adapter.h"
#include "../Adapter.h"

class FilteredAdapter : public FileAdapter {
    public:

        // NewFilteredAdapter is the constructor for FilteredAdapter.
        static FilteredAdapter* NewFilteredAdapter(string filePath) {
            FilteredAdapter* a;
            a->filtered = true;
            a->filePath = filePath;
            return a;
        }

        static bool filterLine(string line, Filter* filter) {
            if(filter == NULL) {
                return false;
            }

            vector<string> p = split(line, ",");
            if(p.size() == 0) {
                return true;
            }

            vector<string> filterSlice;
            string str = trim(p[0]);
            if(str=="p"){
                filterSlice = filter->P;
            } else if(str=="g"){
                filterSlice = filter->G;
            }

            return filterWords(p, filterSlice);
        }

        static bool filterWords(vector<string> line, vector<string> filter) {
            if(line.size() < filter.size()+1) {
                return true;
            }

            bool skipLine;
            for(int i = 0 ; i < filter.size() ; i++){
                if(filter[i].length()>0 && trim(filter[i]) != trim(line[i+1])){
                    skipLine = true;
                    break;
                }
            }

            return skipLine;
        }

        // LoadPolicy loads all policy rules from the storage.
        void LoadPolicy(Model model) {
            this->filtered = false;
            this->LoadPolicy(model);
        }

        // LoadFilteredPolicy loads only policy rules that match the filter.
        void LoadFilteredPolicy(Model model, Filter* filter) {
            if(filter == NULL) {
                this->LoadPolicy(model);
            }

            if(this->filePath == "") {
                throw CasbinAdapterException("Invalid file path, file path cannot be empty");
            }

            this->LoadFilteredPolicyFile(model, filter, LoadPolicyLine);
            this->filtered = true;
        }

        void LoadFilteredPolicyFile(Model model, Filter* filter, void (*handler)(string, Model)) {
            ifstream infile;
            try{
                infile.open(this->filePath);
            } catch (const ifstream::failure e) {
                throw IOException("Cannot open file.");
            }

            string line;
            while(getline(infile, line, '\n')) {
                line = trim(line);
                if(filterLine(line, filter)) {
                    continue;
                }

                handler(line, model);
            }

            infile.close();
        }

        // IsFiltered returns true if the loaded policy has been filtered.
        bool IsFiltered() {
            return this->filtered;
        }

        // SavePolicy saves all policy rules to the storage.
        void SavePolicy(Model model) {
            if(this->filtered) {
                throw CasbinAdapterException("Cannot save a filtered policy");
            }
            this->SavePolicy(model);
        }
};


// Filter defines the filtering rules for a FilteredAdapter's policy. Empty values
// are ignored, but all others must match the filter.
class Filter{
    public:
        vector<string> P;
        vector<string> G;
};

#endif