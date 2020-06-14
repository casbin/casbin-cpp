#ifndef CASBIN_CPP_PERSIST_WATCHER_EX
#define CASBIN_CPP_PERSIST_WATCHER_EX

#include "../model/model.h"
#include "./watcher.h"

// WatcherEx is the strengthen for Casbin watchers.
class WatcherEx: public Watcher {
    public:
        // UpdateForAddPolicy calls the update callback of other instances to synchronize their policy.
        // It is called after Enforcer.AddPolicy()
        virtual void UpdateForAddPolicy(vector<string> params) = 0;

        // UPdateForRemovePolicy calls the update callback of other instances to synchronize their policy.
        // It is called after Enforcer.RemovePolicy()
        virtual void UpdateForRemovePolicy(vector<string> params) = 0;

        // UpdateForRemoveFilteredPolicy calls the update callback of other instances to synchronize their policy.
        // It is called after Enforcer.RemoveFilteredNamedGroupingPolicy()
        virtual void UpdateForRemoveFilteredPolicy(int field_index, vector<string> field_values) = 0;

        // UpdateForSavePolicy calls the update callback of other instances to synchronize their policy.
        // It is called after Enforcer.RemoveFilteredNamedGroupingPolicy()
        virtual void UpdateForSavePolicy(Model* model) = 0;
};

#endif