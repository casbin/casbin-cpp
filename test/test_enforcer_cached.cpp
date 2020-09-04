#pragma once

#include "pch.h"

#include <enforcer_cached.h>

using namespace std;

namespace test_enforcer_cached
{
    TEST_CLASS(TestEnforcerCached)
    {
        public:

            void testEnforceCache(CachedEnforcer& e, string sub,string obj,string act, bool res) {
                Assert::AreEqual(res, e.Enforce({sub,obj,act}));
            }



            TEST_METHOD(TestCache) {
                string model = "../../examples/basic_model.conf";
                string policy = "../../examples/basic_policy.csv";
                CachedEnforcer e = CachedEnforcer(model, policy);
                testEnforceCache(e, "alice", "data1", "read", true);
                testEnforceCache(e, "alice", "data1", "write", false);
                testEnforceCache(e, "alice", "data2", "read", false);
                testEnforceCache(e, "alice", "data2", "write", false);

	            // The cache is enabled, so even if we remove a policy rule, the decision
	            // for ("alice", "data1", "read") will still be true, as it uses the cached result.
                e.RemovePolicy({"alice", "data1", "read"});
	            testEnforceCache(e, "alice", "data1", "read", true);
                testEnforceCache(e, "alice", "data1", "write", false);
                testEnforceCache(e, "alice", "data2", "read", false);
                testEnforceCache(e, "alice", "data2", "write", false);

	            // Now we invalidate the cache, then all first-coming Enforce() has to be evaluated in real-time.
	            // The decision for ("alice", "data1", "read") will be false now.
                e.InvalidateCache();
	            testEnforceCache(e, "alice", "data1", "read", false);
                testEnforceCache(e, "alice", "data1", "write", false);
                testEnforceCache(e, "alice", "data2", "read", false);
                testEnforceCache(e, "alice", "data2", "write", false);
            }

    };
}