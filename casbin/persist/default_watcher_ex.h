#ifndef CASBIN_CPP_PERSIST_DEFAULT_WATCHER
#define CASBIN_CPP_PERSIST_DEFAULT_WATCHER

#include "./watcher_ex.h"

class DefaultWatcherEx: public WatcherEx {
    public:

        template <typename Func>
        void SetUpdateCallback(Func func) {
            return;
        }

        void Update(){
            return;
        }

        void Close(){
            return;
        }
};

#endif