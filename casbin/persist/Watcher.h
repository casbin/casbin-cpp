#ifndef CASBIN_CPP_PERSIST_WATCHER
#define CASBIN_CPP_PERSIST_WATCHER

#include <string>

using namespace std;

// Watcher is the interface for Casbin watchers.
class Watcher {
	// SetUpdateCallback sets the callback function that the watcher will call
	// when the policy in DB has been changed by other instances.
	// A classic callback is Enforcer.LoadPolicy().
	virtual void SetUpdateCallback(void (*func)(string)) = 0;
	// Update calls the update callback of other instances to synchronize their policy.
	// It is usually called after changing the policy in DB, like Enforcer.SavePolicy(),
	// Enforcer.AddPolicy(), Enforcer.RemovePolicy(), etc.
	virtual void Update() = 0;
	// Close stops and releases the watcher, the callback function will not be called any more.
	virtual void Close() = 0;
};

#endif