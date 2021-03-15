#include "pch.h"

#ifndef TEST_ENFORCER_SYNCED_CPP
#define TEST_ENFORCER_SYNCED_CPP

#include <enforcer_synced.h>

using namespace std;

namespace test_enforcer_synced {
TEST_CLASS(TestEnforcerSynced){
    public:

        void testEnforceSync(SyncedEnforcer & e, string sub, string obj, string act, bool res){
            Assert::AreEqual(res, e.Enforce({sub, obj, act}));
        }

        void testAutoLoadRunning(bool test, bool control) {
            Assert::AreEqual(test, control);
        }

TEST_METHOD(TestSync) {
    string model = "../../examples/basic_model.conf";
    string policy = "../../examples/basic_policy.csv";
    SyncedEnforcer e(model, policy);

    chrono::duration<int64_t, std::nano> t = 200ms;
    
    e.StartAutoLoadPolicy(t);

    testEnforceSync(e, "alice", "data1", "read", true);
    testEnforceSync(e, "alice", "data1", "write", false);
    testEnforceSync(e, "alice", "data2", "read", false);
    testEnforceSync(e, "alice", "data2", "write", false);
    testEnforceSync(e, "bob", "data1", "read", false);
    testEnforceSync(e, "bob", "data1", "write", false);
    testEnforceSync(e, "bob", "data2", "read", false);
    testEnforceSync(e, "bob", "data2", "write", true);

    e.StopAutoLoadPolicy();
}

TEST_METHOD(TestStopLoadPolicy) {
    string model = "../../examples/basic_model.conf";
    string policy = "../../examples/basic_policy.csv";
    SyncedEnforcer e(model, policy);

    chrono::duration<int64_t, std::nano> t = 5ms;

    e.StartAutoLoadPolicy(t);

    testAutoLoadRunning(e.IsAutoLoadingRunning(), true);

    testEnforceSync(e, "alice", "data1", "read", true);
    testEnforceSync(e, "alice", "data1", "write", false);
    testEnforceSync(e, "alice", "data2", "read", false);
    testEnforceSync(e, "alice", "data2", "write", false);
    testEnforceSync(e, "bob", "data1", "read", false);
    testEnforceSync(e, "bob", "data1", "write", false);
    testEnforceSync(e, "bob", "data2", "read", false);
    testEnforceSync(e, "bob", "data2", "write", true);

    e.StopAutoLoadPolicy();
    this_thread::sleep_for(10ms);

    testAutoLoadRunning(e.IsAutoLoadingRunning(), false);

}
}
;
}

#endif // TEST_ENFORCER_SYNCED_CPP
