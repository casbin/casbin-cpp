#pragma once

#include "pch.h"

#include <util.h>

using namespace std;

namespace test_built_in_functions
{
    TEST_CLASS(TestBuiltInFunctions)
    {
        public:

            void TestKeyMatch(string key1, string key2, bool res) {
                Scope scope = InitializeScope();
                PushStringValue(scope, key1);
                PushStringValue(scope, key2);

                KeyMatch(scope);
                bool my_res = GetBoolean(scope);

                Assert::AreEqual(res, my_res);
            }

            TEST_METHOD(TestKeyMatch) {
                TestKeyMatch("/foo", "/foo", true);
                TestKeyMatch("/foo", "/foo*", true);
                TestKeyMatch("/foo", "/foo/*", false);
                TestKeyMatch("/foo/bar", "/foo", false);
                TestKeyMatch("/foo/bar", "/foo*", true);
                TestKeyMatch("/foo/bar", "/foo/*", true);
                TestKeyMatch("/foobar", "/foo", false);
                TestKeyMatch("/foobar", "/foo*", true);
                TestKeyMatch("/foobar", "/foo/*", false);
            }

            void TestKeyMatch2(string key1, string key2, bool res) {
                Scope scope = InitializeScope();
                PushStringValue(scope, key1);
                PushStringValue(scope, key2);

                KeyMatch2(scope);
                bool my_res = GetBoolean(scope);

                Assert::AreEqual(res, my_res);
            }

            TEST_METHOD(TestKeyMatch2){
                TestKeyMatch2("/foo", "/foo", true);
                TestKeyMatch2("/foo", "/foo*", true);
                TestKeyMatch2("/foo", "/foo/*", false);
                TestKeyMatch2("/foo/bar", "/foo", false);
                TestKeyMatch2("/foo/bar", "/foo*", false); // different with KeyMatch.
                TestKeyMatch2("/foo/bar", "/foo/*", true);
                TestKeyMatch2("/foobar", "/foo", false);
                TestKeyMatch2("/foobar", "/foo*", false); // different with KeyMatch.
                TestKeyMatch2("/foobar", "/foo/*", false);

                TestKeyMatch2("/", "/:resource", false);
                TestKeyMatch2("/resource1", "/:resource", true);
                TestKeyMatch2("/myid", "/:id/using/:resId", false);
                TestKeyMatch2("/myid/using/myresid", "/:id/using/:resId", true);

                TestKeyMatch2("/proxy/myid", "/proxy/:id/*", false);
                TestKeyMatch2("/proxy/myid/", "/proxy/:id/*", true);
                TestKeyMatch2("/proxy/myid/res", "/proxy/:id/*", true);
                TestKeyMatch2("/proxy/myid/res/res2", "/proxy/:id/*", true);
                TestKeyMatch2("/proxy/myid/res/res2/res3", "/proxy/:id/*", true);
                TestKeyMatch2("/proxy/", "/proxy/:id/*", false);

                TestKeyMatch2("/alice", "/:id", true);
                TestKeyMatch2("/alice/all", "/:id/all", true);
                TestKeyMatch2("/alice", "/:id/all", false);
                TestKeyMatch2("/alice/all", "/:id", false);

                TestKeyMatch2("/alice/all", "/:/all", false);
            }

            void TestKeyMatch3(string key1, string key2, bool res) {
                Scope scope = InitializeScope();
                PushStringValue(scope, key1);
                PushStringValue(scope, key2);

                KeyMatch3(scope);
                bool my_res = GetBoolean(scope);

                Assert::AreEqual(res, my_res);
            }

            TEST_METHOD(TestKeyMatch3){
                // keyMatch3() is similar with KeyMatch2(), except using "/proxy/{id}" instead of "/proxy/:id".
                TestKeyMatch3("/foo", "/foo", true);
                TestKeyMatch3("/foo", "/foo*", true);
                TestKeyMatch3("/foo", "/foo/*", false);
                TestKeyMatch3("/foo/bar", "/foo", false);
                TestKeyMatch3("/foo/bar", "/foo*", false);
                TestKeyMatch3("/foo/bar", "/foo/*", true);
                TestKeyMatch3("/foobar", "/foo", false);
                TestKeyMatch3("/foobar", "/foo*", false);
                TestKeyMatch3("/foobar", "/foo/*", false);

                TestKeyMatch3("/", "/{resource}", false);
                TestKeyMatch3("/resource1", "/{resource}", true);
                TestKeyMatch3("/myid", "/{id}/using/{resId}", false);
                TestKeyMatch3("/myid/using/myresid", "/{id}/using/{resId}", true);

                TestKeyMatch3("/proxy/myid", "/proxy/{id}/*", false);
                TestKeyMatch3("/proxy/myid/", "/proxy/{id}/*", true);
                TestKeyMatch3("/proxy/myid/res", "/proxy/{id}/*", true);
                TestKeyMatch3("/proxy/myid/res/res2", "/proxy/{id}/*", true);
                TestKeyMatch3("/proxy/myid/res/res2/res3", "/proxy/{id}/*", true);
                TestKeyMatch3("/proxy/", "/proxy/{id}/*", false);

                TestKeyMatch3("/myid/using/myresid", "/{id/using/{resId}", false);
            }

            void TestRegexMatch(string key1, string key2, bool res) {
                Scope scope = InitializeScope();
                PushStringValue(scope, key1);
                PushStringValue(scope, key2);

                RegexMatch(scope);
                bool my_res = GetBoolean(scope);

                Assert::AreEqual(res, my_res);
            }

            TEST_METHOD(TestRegexMatch) {
                TestRegexMatch("/topic/create", "/topic/create", true);
                TestRegexMatch("/topic/create/123", "/topic/create", false);
                TestRegexMatch("/topic/delete", "/topic/create", false);
                TestRegexMatch("/topic/edit", "/topic/edit/[0-9]+", false);
                TestRegexMatch("/topic/edit/123", "/topic/edit/[0-9]+", true);
                TestRegexMatch("/topic/edit/abc", "/topic/edit/[0-9]+", false);
                TestRegexMatch("/foo/delete/123", "/topic/delete/[0-9]+", false);
                TestRegexMatch("/topic/delete/0", "/topic/delete/[0-9]+", true);
                TestRegexMatch("/topic/edit/123s", "/topic/delete/[0-9]+", false);
            }

            void TestIPMatch(string ip1, string ip2, bool res) {
                Scope scope = InitializeScope();
                PushStringValue(scope, ip1);
                PushStringValue(scope, ip2);

                IPMatch(scope);
                bool my_res = GetBoolean(scope);

                Assert::AreEqual(res, my_res);
            }

            TEST_METHOD(TestIPMatch) {
                TestIPMatch("192.168.2.123", "192.168.2.0/24", true);
                TestIPMatch("192.168.2.123", "192.168.3.0/24", false);
                TestIPMatch("192.168.2.123", "192.168.2.0/16", true);
                TestIPMatch("192.168.2.123", "192.168.2.123/32", true);
                TestIPMatch("10.0.0.11", "10.0.0.0/8", true);
                TestIPMatch("11.0.0.123", "10.0.0.0/8", false);
            }
    };
}