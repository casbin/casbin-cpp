#ifndef CASBIN_CPP_PERSIST_FILE_ADAPTER_FILTERED_ADAPTER
#define CASBIN_CPP_PERSIST_FILE_ADAPTER_FILTERED_ADAPTER

#include "file_adapter.h"
#include "../filtered_adapter.h"

namespace casbin {

class FilteredFileAdapter : public FileAdapter, public FilteredAdapter {
    private:

        static bool filterLine(std::string line, Filter* filter);

        static bool filterWords(std::vector<std::string> line, std::vector<std::string> filter);

        void loadFilteredPolicyFile(const std::shared_ptr<Model>& model, Filter* filter, std::function<void(std::string, const std::shared_ptr<Model>&)> handler);

    public:

        // NewFilteredAdapter is the constructor for FilteredAdapter.
        FilteredFileAdapter(std::string file_path);

        // LoadPolicy loads all policy rules from the storage.
        void LoadPolicy(const std::shared_ptr<Model>& model);

        // LoadFilteredPolicy loads only policy rules that match the filter.
        void LoadFilteredPolicy(const std::shared_ptr<Model>& model, Filter* filter);

        // IsFiltered returns true if the loaded policy has been filtered.
        bool IsFiltered();

        // SavePolicy saves all policy rules to the storage.
        void SavePolicy(const std::shared_ptr<Model>& model);
};

};  // namespace casbin

#endif