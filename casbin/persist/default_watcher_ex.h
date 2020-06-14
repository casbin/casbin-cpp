#ifndef CASBIN_CPP_PERSIST_DEFAULT_WATCHER_EX
#define CASBIN_CPP_PERSIST_DEFAULT_WATCHER_EX

#include "./watcher_ex.h"

class DefaultWatcherEx: public WatcherEx {
    public:

        void UpdateForAddPolicy(vector<string> params);

        void UpdateForRemovePolicy(vector<string> params);

        void UpdateForRemoveFilteredPolicy(int field_index, vector<string> field_values);

        void UpdateForSavePolicy(Model* model);
};

#endif