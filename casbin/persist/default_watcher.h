#ifndef CASBIN_CPP_PERSIST_DEFAULT_WATCHER
#define CASBIN_CPP_PERSIST_DEFAULT_WATCHER

#include "./watcher.h"

class DefaultWatcher: public Watcher {
    public:

        void UpdateForAddPolicy(vector<string> params) {
            return;
        }

        void UpdateForRemovePolicy(vector<string> params) {
            return;
        }

        void UpdateForRemoveFilteredPolicy(int field_index, vector<string> field_values) {
            return;
        }

        void UpdateForSavePolicy(Model* model) {
            return;
        }
};

#endif