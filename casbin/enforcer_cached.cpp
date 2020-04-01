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

auto CachedEnforcer::enforce() -> bool
{
	return false;
}
