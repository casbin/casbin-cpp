#include "enforcer_cached.h"

CachedEnforcer::CachedEnforcer(const string& model_file) : Enforcer(model_file) {

}

CachedEnforcer::CachedEnforcer(const string& model_file, const string& policy_file) : Enforcer(model_file, policy_file) {

}

CachedEnforcer::CachedEnforcer(const string& model_file, Adapter* policy_adapter) : Enforcer(model_file, policy_adapter) {

}

auto CachedEnforcer::enable_cache(const bool enable_c) -> void
{
	enable_cache_ = enable_c;
}

auto CachedEnforcer::enforce(const string& sub, const string& obj, const string& act) -> bool
{
	if(!enable_cache_) return Enforcer::enforce(sub, obj, act);

	const auto key = sub + "$$" + obj + "$$" + act;
	auto cache_result = get_cached_result(key);
	if(get<1>(cache_result))
		return get<0>(cache_result);

	const auto result = Enforcer::enforce(sub, obj, act);
	set_cached_result(key, result);
	return result;
}

auto CachedEnforcer::get_cached_result(const string& key) -> tuple<bool, bool>
{
	if(m_.find(key) != m_.end()) return make_pair(m_.find(key)->second, true);
	return make_pair(NULL, false);
	
}

void CachedEnforcer::set_cached_result(const string& key, const bool& val)
{
	m_.insert({ key, val });
}