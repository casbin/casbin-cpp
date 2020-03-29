#ifndef CASBIN_CPP_PERSIST_ADAPTER_FILTERED
#define CASBIN_CPP_PERSIST_ADAPTER_FILTERED

#include "./Adapter.h"

// FilteredAdapter is the interface for Casbin adapters supporting filtered policies.
class FilteredAdapter : public Adapter {
    public:

        // LoadFilteredPolicy loads only policy rules that match the filter.
        template <typename Filter>
        void LoadFilteredPolicy(Model model, Filter filter);
        // IsFiltered returns true if the loaded policy has been filtered.
        virtual bool IsFiltered() = 0;
};

#endif