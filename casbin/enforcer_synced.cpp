#include "pch.h"
#include "./enforcer_synced.h"



/**
 * Enforcer is the default constructor.
 */
SyncedEnforcer ::SyncedEnforcer() {
    stopAutoLoad = Channel<int>(1);
    autoLoadRunning = 0;
}

/**
 * Enforcer initializes an enforcer with a model file and a policy file.
 *
 * @param model_path the path of the model file.
 * @param policyFile the path of the policy file.
 */
SyncedEnforcer ::SyncedEnforcer(string model_path, string policy_file)
    : Enforcer(model_path, policy_file) {
    stopAutoLoad = Channel<int>(1);
    autoLoadRunning = 0;
}

/**
 * Enforcer initializes an enforcer with a database adapter.
 *
 * @param model_path the path of the model file.
 * @param adapter the adapter.
 */
SyncedEnforcer ::SyncedEnforcer(string model_path, shared_ptr<Adapter> adapter)
    : Enforcer(model_path, adapter) {
    stopAutoLoad = Channel<int>(1);
    autoLoadRunning = 0;
}

/**
 * Enforcer initializes an enforcer with a model and a database adapter.
 *
 * @param m the model.
 * @param adapter the adapter.
 */
SyncedEnforcer ::SyncedEnforcer(shared_ptr<Model> m, shared_ptr<Adapter> adapter): Enforcer(m, adapter) {
    stopAutoLoad = Channel<int>(1);
    autoLoadRunning = 0;
}

/**
 * Enforcer initializes an enforcer with a model.
 *
 * @param m the model.
 */
SyncedEnforcer ::SyncedEnforcer(shared_ptr<Model> m)
    : Enforcer(m) {
    stopAutoLoad = Channel<int>(1);
    autoLoadRunning = 0;
}

/**
 * Enforcer initializes an enforcer with a model file.
 *
 * @param model_path the path of the model file.
 */
SyncedEnforcer ::SyncedEnforcer(string model_path)
    : Enforcer(model_path) {
    stopAutoLoad = Channel<int>(1);
    autoLoadRunning = 0;
}

/**
 * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
 *
 * @param model_path the path of the model file.
 * @param policyFile the path of the policy file.
 * @param enableLog whether to enable Casbin's log.
 */
SyncedEnforcer ::SyncedEnforcer(string model_path, string policy_file, bool enable_log)
    : Enforcer(model_path, policy_file, enable_log) {
    stopAutoLoad = Channel<int>(1);
    autoLoadRunning = 0;
}

SyncedEnforcer::SyncedEnforcer(SyncedEnforcer&& se) {
    this->stopAutoLoad = move(se.stopAutoLoad);
    this->autoLoadRunning = se.autoLoadRunning.load();
}

bool SyncedEnforcer::IsAutoLoadingRunning() {
    return autoLoadRunning.load();
}

void SyncedEnforcer::StartAutoLoadPolicy(chrono::duration<int, milli> duration) {
    if (IsAutoLoadingRunning()) {
        return;
    }
    autoLoadRunning.store(1);
    Ticker<int> ticker = Ticker<int>(duration,1);
    int n = 1;
    bool flag = true;
    while (flag) {

        Select<int> s;
        int i;
        s.recv(ticker.c, i, [&n, this]() {
            this->LoadPolicy();
            n++;
        });
        s.recv(this->stopAutoLoad, i, [&flag] { flag = false; });
    }
    return;
}

void SyncedEnforcer::StopAutoLoadPolicy() {
    if (IsAutoLoadingRunning()) {
        stopAutoLoad.send(1);
    }
}

void SyncedEnforcer::SetWatcher(shared_ptr<Watcher> watcher) {
   this->watcher = watcher;
    return watcher->SetUpdateCallback([this]() { this->LoadPolicy(); });
}

void SyncedEnforcer::ClearPolciy() {
    lock.lock();
    Enforcer::ClearPolicy();
    lock.unlock();
}

void SyncedEnforcer::LoadPolicy() {
    lock.lock();
    Enforcer::LoadPolicy();
    lock.unlock();
}

void SyncedEnforcer::LoadFilteredPolicy(Filter filter) {
    lock.lock();
    Enforcer::LoadFilteredPolicy(filter);
    lock.unlock();
}


void SyncedEnforcer::LoadIncrementalFilteredPolicy(Filter filter) {
    lock.lock();
    //Enforcer::LoadIncrementalFilteredPolicy(filter);
    lock.unlock();
}

void SyncedEnforcer::SavePolicy() {
    lock.lock();
    Enforcer::SavePolicy();
    lock.unlock();
}

void SyncedEnforcer::BuildRoleLinks() {
    lock.lock();
    Enforcer::BuildRoleLinks();
    lock.unlock();
}

bool SyncedEnforcer::Enforce(Scope scope) {
    lock.lock();
    bool ans = Enforcer::Enforce(scope);
    lock.unlock();
    return ans;
}

// Enforce with a vector param,decides whether a "subject" can access a
// "object" with the operation "action", input parameters are usually: (sub,
// obj, act).
bool SyncedEnforcer::Enforce(vector<string> params) {
    lock.lock();
    bool ans = Enforcer::Enforce(params);
    lock.unlock();
    return ans;
}

// Enforce with a map param,decides whether a "subject" can access a "object"
// with the operation "action", input parameters are usually: (sub, obj, act).
bool SyncedEnforcer::Enforce(unordered_map<string, string> params) {
    lock.lock();
    bool ans = Enforcer::Enforce(params);
    lock.unlock();
    return ans;
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can
// access a "object" with the operation "action", input parameters are
// usually: (matcher, sub, obj, act), use model matcher by default when
// matcher is "".
bool SyncedEnforcer::EnforceWithMatcher(string matcher, Scope scope) {
    lock.lock();
    bool ans = Enforcer::EnforceWithMatcher(matcher,scope);
    lock.unlock();
    return ans;
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can
// access a "object" with the operation "action", input parameters are
// usually: (matcher, sub, obj, act), use model matcher by default when
// matcher is "".
bool SyncedEnforcer::EnforceWithMatcher(string matcher, vector<string> params) {
    lock.lock();
    bool ans = Enforcer::EnforceWithMatcher(matcher,params);
    lock.unlock();
    return ans;
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can
// access a "object" with the operation "action", input parameters are
// usually: (matcher, sub, obj, act), use model matcher by default when
// matcher is "".
bool SyncedEnforcer::EnforceWithMatcher(string matcher, unordered_map<string, string> params) {
    lock.lock();
    bool ans = Enforcer::EnforceWithMatcher(matcher,params);
    lock.unlock();
    return ans;
}

vector<string> SyncedEnforcer::GetAllSubjects() {
    lock.lock();
    auto res = Enforcer::GetAllSubjects();
    lock.unlock();
    return res;
}

vector<string> SyncedEnforcer::GetAllNamedSubjects(string p_type) {
    lock.lock();
    auto res = Enforcer::GetAllNamedSubjects(p_type);
    lock.unlock();
    return res;
}

vector<string> SyncedEnforcer::GetAllObjects() {
    lock.lock();
    auto res = Enforcer::GetAllObjects();
    lock.unlock();
    return res;
}

vector<string> SyncedEnforcer::GetAllNamedObjects(string p_type) {
    lock.lock();
    auto res = Enforcer::GetAllNamedObjects(p_type);
    lock.unlock();
    return res;
}

vector<string> SyncedEnforcer::GetAllActions() {
    lock.lock();
    auto res = Enforcer::GetAllActions();
    lock.unlock();
    return res;
}

vector<string> SyncedEnforcer::GetAllNamedActions(string p_type) {
    lock.lock();
    auto res = Enforcer::GetAllNamedActions(p_type);
    lock.unlock();
    return res;
}

vector<string> SyncedEnforcer::GetAllRoles() {
    lock.lock();
    auto res = Enforcer::GetAllRoles();
    lock.unlock();
    return res;
}

vector<string> SyncedEnforcer::GetAllNamedRoles(string p_type) {
    lock.lock();
    auto res = Enforcer::GetAllNamedRoles(p_type);
    lock.unlock();
    return res;
}

vector<vector<string>> SyncedEnforcer::GetPolicy() {
    lock.lock();
    auto res = Enforcer::GetPolicy();
    lock.unlock();
    return res;
}

vector<vector<string>> SyncedEnforcer::GetFilteredPolicy(int field_index, vector<string> field_values) {
    lock.lock();
    auto res = Enforcer::GetFilteredPolicy(field_index,field_values);
    lock.unlock();
    return res;
}

vector<vector<string>> SyncedEnforcer::GetNamedPolicy(string p_type) {
    lock.lock();
    auto res = Enforcer::GetNamedPolicy(p_type);
    lock.unlock();
    return res;
}

vector<vector<string>> SyncedEnforcer::GetFilteredNamedPolicy(string p_type, int field_index, vector<string> field_values) {
    lock.lock();
    auto res = Enforcer::GetFilteredNamedPolicy(p_type,field_index,field_values);
    lock.unlock();
    return res;
}

vector<vector<string>> SyncedEnforcer::GetGroupingPolicy() {
    lock.lock();
    auto res = Enforcer::GetGroupingPolicy();
    lock.unlock();
    return res;
}

vector<vector<string>> SyncedEnforcer::GetFilteredGroupingPolicy(int field_index, vector<string> field_values) {
    lock.lock();
    auto res = Enforcer::GetFilteredGroupingPolicy(field_index,field_values);
    lock.unlock();
    return res;
}

vector<vector<string>> SyncedEnforcer::GetNamedGroupingPolicy(string p_type) {
    lock.lock();
    auto res = Enforcer::GetNamedGroupingPolicy(p_type);
    lock.unlock();
    return res;
}

vector<vector<string>> SyncedEnforcer::GetFilteredNamedGroupingPolicy(string p_type, int field_index, vector<string> field_values) {
    lock.lock();
    auto res = Enforcer::GetFilteredNamedGroupingPolicy(p_type,field_index,field_values);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::HasPolicy(vector<string> params) {
    lock.lock();
    bool res = Enforcer::HasPolicy(params);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::HasNamedPolicy(string p_type, vector<string> params) {
    lock.lock();
    bool res = Enforcer::HasNamedPolicy(p_type,params);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::AddPolicy(vector<string> params) {
    lock.lock();
    bool res = Enforcer::AddPolicy(params);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::AddPolicies(vector<vector<string>> rules) {
    lock.lock();
    bool res = Enforcer::AddPolicies(rules);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::AddNamedPolicy(string p_type, vector<string> params) {
    lock.lock();
    bool res = Enforcer::AddNamedPolicy(p_type,params);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::AddNamedPolicies(string p_type, vector<vector<string>> rules) {
    lock.lock();
    bool res = Enforcer::AddNamedPolicies(p_type,rules);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::RemovePolicy(vector<string> params) {
    lock.lock();
    bool res = Enforcer::RemovePolicy(params);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::RemovePolicies(vector<vector<string>> rules) {
    lock.lock();
    bool res = Enforcer::RemovePolicies(rules);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::RemoveFilteredPolicy(int field_index, vector<string> field_values) {
    lock.lock();
    bool res = Enforcer::RemoveFilteredPolicy(field_index,field_values);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::RemoveNamedPolicy(string p_type, vector<string> params) {
    lock.lock();
    bool res = Enforcer::RemoveNamedPolicy(p_type,params);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::RemoveNamedPolicies(string p_type, vector<vector<string>> rules) {
    lock.lock();
    bool res = Enforcer::RemoveNamedPolicies(p_type,rules);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::RemoveFilteredNamedPolicy(string p_type, int field_index, vector<string> field_values) {
    lock.lock();
    bool res = Enforcer::RemoveFilteredNamedPolicy(p_type,field_index,field_values);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::HasGroupingPolicy(vector<string> params) {
    lock.lock();
    bool res = Enforcer::HasGroupingPolicy(params);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::HasNamedGroupingPolicy(string p_type, vector<string> params) {
    lock.lock();
    bool res = Enforcer::HasNamedGroupingPolicy(p_type,params);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::AddGroupingPolicy(vector<string> params) {
    lock.lock();
    bool res = Enforcer::AddGroupingPolicy(params);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::AddGroupingPolicies(vector<vector<string>> rules) {
    lock.lock();
    bool res = Enforcer::AddGroupingPolicies(rules);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::AddNamedGroupingPolicy(string p_type, vector<string> params) {
    lock.lock();
    bool res = Enforcer::AddNamedGroupingPolicy(p_type,params);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::AddNamedGroupingPolicies(string p_type, vector<vector<string>> rules) {
    lock.lock();
    bool res = Enforcer::AddNamedGroupingPolicies(p_type,rules);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::RemoveGroupingPolicy(vector<string> params) {
    lock.lock();
    bool res = Enforcer::RemoveGroupingPolicy(params);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::RemoveGroupingPolicies(vector<vector<string>> rules) {
    lock.lock();
    bool res = Enforcer::RemoveGroupingPolicies(rules);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::RemoveFilteredGroupingPolicy(int field_index, vector<string> field_values) {
    lock.lock();
    bool res = Enforcer::RemoveFilteredGroupingPolicy(field_index,field_values);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::RemoveNamedGroupingPolicy(string p_type, vector<string> params) {
    lock.lock();
    bool res = Enforcer::RemoveNamedGroupingPolicy(p_type,params);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::RemoveNamedGroupingPolicies(string p_type, vector<vector<string>> rules) {
    lock.lock();
    bool res = Enforcer::RemoveNamedGroupingPolicies(p_type,rules);
    lock.unlock();
    return res;
}

bool SyncedEnforcer::RemoveFilteredNamedGroupingPolicy(string p_type, int field_index, vector<string> field_values) {
    lock.lock();
    bool res = Enforcer::RemoveFilteredNamedGroupingPolicy(p_type,field_index,field_values);
    lock.unlock();
    return res;
}

void SyncedEnforcer::AddFunction(string name, Function function, Index nargs) {
    lock.lock();
    Enforcer::AddFunction(name,function,nargs);
    lock.unlock();
}
