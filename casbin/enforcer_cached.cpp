#pragma once
#include "enforcer_cached.h"

CachedEnforcer::CachedEnforcer(CachedEnforcer& e) {
	//cout << "copy cached" << endl;
	modelPath = e.modelPath;
	model = move(e.model);
	//e.model->PrintModel();
	eft = e.eft;
	tm = e.tm;
	fm = e.fm;
	adapter = move(e.adapter);
	//Watcher* watcher;
	rm = move(e.rm);
	enabled = e.enabled;
	autoSave = e.autoSave;
	autoBuildRoleLinks = e.autoBuildRoleLinks;
	autoNotifyWatcher = e.autoNotifyWatcher;
	m = e.m;
	enableCache = e.enableCache;
}

/*
CachedEnforcer::CachedEnforcer(unique_ptr<Model>& model, const string& policyPath) {
	Enforcer::Enforcer( model,policyPath);
	enableCache = false;
}

CachedEnforcer::CachedEnforcer(const string& modelPath, unique_ptr<Adapter>& adapter) {
	Enforcer::Enforcer(modelPath, adapter);
	enableCache = false;
}*/

CachedEnforcer::CachedEnforcer(unique_ptr<Model>& model, unique_ptr<Adapter>& adapter): Enforcer(model, adapter){
	enableCache = false;
}

CachedEnforcer::CachedEnforcer(const string& modelPath, const string& policyPath): Enforcer(modelPath, policyPath) {
	cout << "CachedEnforcer" << endl;
	enableCache = false;
}

void CachedEnforcer::EnableCache(const bool& enableCache) {
	this->enableCache = enableCache;
}

bool CachedEnforcer::Enforce(const vector<string>& rval) {
	if (!enableCache){
		return Enforcer::Enforce(rval);
	}

	string key;
	for (auto r : rval) {
		key += r;
		key += "$$";
	}

	pair<bool, bool> res_ok = getCachedResult(key);

	if (res_ok.second) {
		cout << "get cached:" << res_ok.first <<endl;
		return res_ok.first;
	}

	bool res = Enforcer::Enforce(rval);
	setCachedResult(key, res);
	return res;
}

pair<bool, bool> CachedEnforcer::getCachedResult(const string& key) {
	locker.lock();
	bool ok = m.count(key);
	if (!ok)
	{
		locker.unlock();
		return pair<bool, bool>(false, false);
	}

	pair <bool, bool>res_ok(m[key],ok);
	locker.unlock();
	return res_ok;
}

void CachedEnforcer::setCachedResult(const string& key, const bool& res) {
	locker.lock();
	m[key] = res;
	locker.unlock();
}

void CachedEnforcer::InvalidateCache() {
	m.clear();
}