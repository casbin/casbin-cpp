#pragma once

#include "pch.h"

#include <enforcer_synced.h>

using namespace std;

namespace test_enforcer_synced
{
    TEST_CLASS(TestEnforcerCached)
    {
        public:

            void testEnforcerSync(SyncedEnforcer& e, string sub,string obj,string act, bool res) {
                Assert::AreEqual(res, e.Enforce({sub,obj,act}));
            }



            TEST_METHOD(TestSync) {
                string model = "../../examples/basic_model.conf";
                string policy = "../../examples/basic_policy.csv";
                SyncedEnforcer e = SyncedEnforcer(model, policy);
                //e.StartAutoLoadPolicy(chrono::duration<int, milli>(200));

                testEnforcerSync(e, "alice", "data1", "read", true);
                testEnforcerSync(e, "alice", "data1", "write", false);
                testEnforcerSync(e, "alice", "data2", "read", false);
                testEnforcerSync(e, "alice", "data2", "write", false);
	            testEnforcerSync(e, "bob", "data1", "read", false);
                testEnforcerSync(e, "bob", "data1", "write", false);
                testEnforcerSync(e, "bob", "data2", "read", false);
                testEnforcerSync(e, "bob", "data2", "write", true);
	          
                //e.StopAutoLoadPolicy();
            }

            TEST_METHOD(TestStopAutoPolicy) {
                string model = "../../examples/basic_model.conf";
                string policy = "../../examples/basic_policy.csv";
                SyncedEnforcer e = SyncedEnforcer(model, policy);
                
                //e.StartAutoLoadPolicy(chrono::duration<int, milli>(200));
                //Assert::AreEqual(e.IsAutoLoadingRunning(),true);
                //e.StopAutoLoadPolicy();
                //Assert::AreEqual(e.IsAutoLoadingRunning(),false);
                
            }

    };
}