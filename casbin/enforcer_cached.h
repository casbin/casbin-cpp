#pragma once

#ifdef CASBIN_EXPORTS
#define ENFORCER_CACHED_API __declspec(dllexport)
#else
#define ENFORCER_CACHED_API __declspec(dllimport)
#endif

#include <unordered_map>
#include "enforcer.h"


class ENFORCER_CACHED_API CachedEnforcer :public Enforcer {
public:
	unordered_map<string, bool> m;
	bool enableCache;
	mutex locker;

	CachedEnforcer(CachedEnforcer& e);
	//CachedEnforcer(unique_ptr<Model>& model, const string& policyPath);
	//CachedEnforcer(const string& modelPath, unique_ptr<Adapter>& adapter);

	CachedEnforcer(unique_ptr<Model>& model, unique_ptr<Adapter>& adapter);
	CachedEnforcer(const string& modelPath, const string& policyPath);
	
	void EnableCache(const bool& enableCache);
	bool Enforce(const vector<string>& rval);
	pair<bool,bool> getCachedResult(const string& key);
	void setCachedResult(const string& key, const bool& res);
	void InvalidateCache();
};