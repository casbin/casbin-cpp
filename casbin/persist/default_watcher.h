#ifndef CASBIN_CPP_PERSIST_DEFAULT_WATCHER
#define CASBIN_CPP_PERSIST_DEFAULT_WATCHER

#include "./watcher.h"

class DefaultWatcher: public Watcher {
    public:

        template <typename Func>
        void SetUpdateCallback(Func func);

        void Update();

        void Close();
};

#endif