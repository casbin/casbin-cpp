#pragma once

#ifdef CASBIN_EXPORTS
#define CACHED_ENFORCER_API __declspec(dllexport)
#else
#define CACHED_ENFORCER_API __declspec(dllimport)
#endif

#include <unordered_map>
#include <shared_mutex>
#include <tuple>
#include "enforcer.h"

using namespace std;

class CACHED_ENFORCER_API CachedEnforcer : private Enforcer {
	bool enable_cache_ = false;
	unordered_map<string, bool> m_;
	mutable shared_mutex locker_;

public:
	explicit CachedEnforcer(const string&);
	CachedEnforcer(const string&, const string&);
	CachedEnforcer(const string&, Adapter*);
	auto enable_cache(bool) -> void;
	auto enforce(const string& sub, const string& obj, const string& act) -> bool;
	auto get_cached_result(const string& key) -> tuple<bool, bool>;
	void set_cached_result(const string& key, const bool& val);
};