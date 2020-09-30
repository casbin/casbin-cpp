#pragma once

#include "pch.h"

#include <enforcer.h>
#include <persist.h>
#include <rbac.h>
#include <util.h>

#define N 100

using namespace std;



namespace test_model_Benchmark
{

    TEST_CLASS(TestModelBenchmark)
    {
    public:
        bool rawEnforce(string sub, string obj, string act){
            vector<vector<string>> policy = {{"alice", "data1", "read"}, {"bob", "data2", "write"}};
            for (auto& rule : policy) {
                if (sub == rule[0] && obj == rule[1] && act == rule[2]) {
                    return true;
                }
            }
            return false;
        }

        TEST_METHOD(BenchMarkRaw) {
            for( int i = 0; i < N; i++) {
                rawEnforce("alice", "data1", "read");
	        }
        }

        TEST_METHOD(BenchmarkBasicModel) {
            Enforcer e = Enforcer("../../examples/basic_model.conf", "../../examples/basic_policy.csv");
            for( int i = 0; i < N; i++) {
               e.Enforce({"alice", "data1", "read"});
	        }
        }
        
        TEST_METHOD(BenchmarkRBACModel) {
            Enforcer e = Enforcer("../../examples/rbac_model.conf", "../../examples/rbac_policy.csv");
            for( int i = 0; i < N; i++) {
                e.Enforce({"alice", "data2", "read"});
	        }
        }
        
        /*
        TEST_METHOD(BenchmarkRBACModelSmall) {
            Enforcer e = Enforcer ("../../examples/rbac_model.conf");
            vector<vector<string>> pPolicies;
            vector<vector<string>> gPolicies;

            for (int i = 0; i < 100; i++) {
                e.AddPolicy({string("group")+to_string(i),string("data")+to_string(i/10)});
            }

            //e.AddPolicies(pPolicies);

            for (int i = 0; i < 1000; i++) {
                e.AddGroupingPolicy({string("user")+to_string(i),string("group")+to_string(i/10)});
            }

            //e.AddGroupingPolicies(gPolicies);

            for( int i = 0; i < N; i++) {
                e.Enforce({"user501", "data9", "read"});
	        }
        }


        TEST_METHOD(BenchmarkRBACModelMedium) {
            Enforcer e = Enforcer ("../../examples/rbac_model.conf");
            vector<vector<string>> pPolicies;
            vector<vector<string>> gPolicies;

            for (int i = 0; i < 1000; i++) {
                pPolicies.push_back({string("group")+to_string(i),string("data")+to_string(i/10)});
            }

            e.AddPolicies(pPolicies);

            for (int i = 0; i < 10000; i++) {
                gPolicies.push_back({string("user")+to_string(i),string("group")+to_string(i/10)});
            }

            e.AddGroupingPolicies(gPolicies);

            for( int i = 0; i < N; i++) {
                e.Enforce({"user5001", "data99", "read"});
	        }
        }


        TEST_METHOD(BenchmarkRBACModelLarge) {
            Enforcer e = Enforcer ("../../examples/rbac_model.conf");
            vector<vector<string>> pPolicies;
            vector<vector<string>> gPolicies;

            for (int i = 0; i < 10000; i++) {
                pPolicies.push_back({string("group")+to_string(i),string("data")+to_string(i/10)});
            }

            e.AddGroupingPolicies(pPolicies);

            for (int i = 0; i < 100000; i++) {
                gPolicies.push_back({string("user")+to_string(i),string("group")+to_string(i/10)});
            }

            e.AddGroupingPolicies(gPolicies);
            for( int i = 0; i < N; i++) {
                e.Enforce({"user50001", "data999", "read"});
	        }
        }
        */

        TEST_METHOD(BenchmarkRBACModelWithResourceRoles) {
            Enforcer e = Enforcer ("../../examples/rbac_with_resource_roles_model.conf", "../../examples/rbac_with_resource_roles_policy.csv");
            for( int i = 0; i < N; i++) {
                e.Enforce({"alice", "data1", "read"});
	        }
        }

        TEST_METHOD(BenchmarkRBACModelWithDomains) {
            Enforcer e = Enforcer("../../examples/rbac_with_domains_model.conf", "../../examples/rbac_with_domains_policy.csv");
            for( int i = 0; i < N; i++) {
                e.Enforce({"alice", "domain1", "data1", "read"});
	        }
        }

        /*
        TEST_METHOD(BenchmarkABACModel) {
            Enforcer e = Enforcer("../../examples/abac_model.conf"));
            for( int i = 0; i < N; i++) {
                ve[7].Enforce({"alice", "data1", "read"});
	        }
        }
        */

        TEST_METHOD(BenchmarkKeyMatchModel) {
            Enforcer e = Enforcer("../../examples/keymatch_model.conf", "../../examples/keymatch_policy.csv");
            for( int i = 0; i < N; i++) {
                e.Enforce({"alice", "/alice_data/resource1", "GET"});
	        }
        }

        TEST_METHOD(BenchmarkRBACModelWithDeny) {
            Enforcer e = Enforcer("../../examples/rbac_with_deny_model.conf", "../../examples/rbac_with_deny_policy.csv");
            for( int i = 0; i < N; i++) {
                e.Enforce({"alice", "data1", "read"});
	        }
        }

        TEST_METHOD(BenchmarkPriorityModel) {
            Enforcer e = Enforcer("../../examples/priority_model.conf", "../../examples/priority_policy.csv");
            for( int i = 0; i < N; i++) {
                e.Enforce({"alice", "data1", "read"});
	        }
        }
    };
}