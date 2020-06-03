#ifndef CASBIN_CPP_PERSIST_DEFAULT_WATCHER
#define CASBIN_CPP_PERSIST_DEFAULT_WATCHER

#include "./Watcher.h"

class DefaultWatcher : public Watcher {
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