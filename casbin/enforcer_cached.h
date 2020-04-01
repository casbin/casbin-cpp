#pragma once
#include <unordered_map>
#include <shared_mutex>
#include "enforcer.h"

using namespace std;

class CachedEnforcer : private Enforcer {
	bool enable_cache_ = false;
	unordered_map<string, bool> m_;
	mutable shared_mutex locker_;

public:
	explicit CachedEnforcer(const string&);
	CachedEnforcer(const string&, const string&);
	CachedEnforcer(const string&, Adapter*);
	auto enable_cache(bool) -> void;
	auto enforce() -> bool;
};