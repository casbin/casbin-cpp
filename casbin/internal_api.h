#ifndef CASBIN_CPP_INTERNAL_API
#define CASBIN_CPP_INTERNAL_API

#include "./enforcer.h"

// addPolicy adds a rule to the current policy.
bool Enforcer :: addPolicy(string sec, string ptype, vector<string> rule) {
	bool ruleAdded = this->model.AddPolicy(sec, ptype, rule);
	if(!ruleAdded)
		return ruleAdded;

	if(this->adapter != NULL && this->autoSave)
        this->adapter->AddPolicy(sec, ptype, rule);

	if(this->watcher != NULL && this->autoNotifyWatcher)
		this->watcher->Update();

	return ruleAdded;
}

// removePolicy removes a rule from the current policy.
bool Enforcer :: removePolicy(string sec, string ptype, vector<string> rule) {
	bool ruleRemoved = this->model.RemovePolicy(sec, ptype, rule);
	if(!ruleRemoved)
		return ruleRemoved;

	if(this->adapter != NULL && this->autoSave)
        this->adapter->RemovePolicy(sec, ptype, rule);

	if(this->watcher !=NULL && this->autoNotifyWatcher)
		this->watcher->Update();

	return ruleRemoved;
}

// removeFilteredPolicy removes rules based on field filters from the current policy.
bool Enforcer :: removeFilteredPolicy(string sec, string ptype, int fieldIndex, vector<string> fieldValues){
	bool ruleRemoved  = this->model.RemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues);
	if(!ruleRemoved)
		return ruleRemoved;

	if(this->adapter != NULL && this->autoSave)
        this->adapter->RemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues);

	if(this->watcher !=NULL && this->autoNotifyWatcher)
		this->watcher->Update();

	return ruleRemoved;
}

#endif