/*
* Copyright 2021 The casbin Authors. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* This is a test file for testing built in functions in casbin
*/

#include <gtest/gtest.h>
#include <casbin/casbin.h>

namespace {

void TestKeyMatchFn(std::string key1, std::string key2, bool res){
    auto  evaluator = casbin::ExprtkEvaluator();
    auto func = casbin::ExprtkFunctionFactory::GetExprtkFunction(casbin::ExprtkFunctionType::KeyMatch, 2);
    evaluator.AddFunction("keyMatch", func);
    evaluator.AddIdentifier("key1", key1);
    evaluator.AddIdentifier("key2", key2);
    evaluator.Eval("keyMatch(key1, key2)");
    bool my_res = evaluator.GetBoolen();
    EXPECT_EQ(res, my_res);
}

TEST(TestBuiltInFunctions, TestKeyMatch) {
    TestKeyMatchFn("/foo", "/foo", true);
    TestKeyMatchFn("/foo", "/foo*", true);
    TestKeyMatchFn("/foo", "/foo/*", false);
    TestKeyMatchFn("/foo/bar", "/foo", false);
    TestKeyMatchFn("/foo/bar", "/foo*", true);
    TestKeyMatchFn("/foo/bar", "/foo/*", true);
    TestKeyMatchFn("/foobar", "/foo", false);
    TestKeyMatchFn("/foobar", "/foo*", true);
    TestKeyMatchFn("/foobar", "/foo/*", false);
}

void TestKeyMatch2Fn(std::string key1, std::string key2, bool res) {
    auto  evaluator = casbin::ExprtkEvaluator();
    auto func = casbin::ExprtkFunctionFactory::GetExprtkFunction(casbin::ExprtkFunctionType::KeyMatch2, 2);
    evaluator.AddFunction("keyMatch2", func);
    evaluator.AddIdentifier("key1", key1);
    evaluator.AddIdentifier("key2", key2);
    evaluator.Eval("keyMatch2(key1, key2)");
    bool my_res = evaluator.GetBoolen();

    EXPECT_EQ(res, my_res);
}

TEST(TestBuiltInFunctions, TestKeyMatch2){
    TestKeyMatch2Fn("/foo", "/foo", true);
    TestKeyMatch2Fn("/foo", "/foo*", true);
    TestKeyMatch2Fn("/foo", "/foo/*", false);
    TestKeyMatch2Fn("/foo/bar", "/foo", false);
    TestKeyMatch2Fn("/foo/bar", "/foo*", false); // different with KeyMatch.
    TestKeyMatch2Fn("/foo/bar", "/foo/*", true);
    TestKeyMatch2Fn("/foobar", "/foo", false);
    TestKeyMatch2Fn("/foobar", "/foo*", false); // different with KeyMatch.
    TestKeyMatch2Fn("/foobar", "/foo/*", false);

    TestKeyMatch2Fn("/", "/:resource", false);
    TestKeyMatch2Fn("/resource1", "/:resource", true);
    TestKeyMatch2Fn("/myid", "/:id/using/:resId", false);
    TestKeyMatch2Fn("/myid/using/myresid", "/:id/using/:resId", true);

    TestKeyMatch2Fn("/proxy/myid", "/proxy/:id/*", false);
    TestKeyMatch2Fn("/proxy/myid/", "/proxy/:id/*", true);
    TestKeyMatch2Fn("/proxy/myid/res", "/proxy/:id/*", true);
    TestKeyMatch2Fn("/proxy/myid/res/res2", "/proxy/:id/*", true);
    TestKeyMatch2Fn("/proxy/myid/res/res2/res3", "/proxy/:id/*", true);
    TestKeyMatch2Fn("/proxy/", "/proxy/:id/*", false);

    TestKeyMatch2Fn("/alice", "/:id", true);
    TestKeyMatch2Fn("/alice/all", "/:id/all", true);
    TestKeyMatch2Fn("/alice", "/:id/all", false);
    TestKeyMatch2Fn("/alice/all", "/:id", false);

    TestKeyMatch2Fn("/alice/all", "/:/all", false);
}

void TestKeyMatch3Fn(std::string key1, std::string key2, bool res) {
    auto  evaluator = casbin::ExprtkEvaluator();
    auto func = casbin::ExprtkFunctionFactory::GetExprtkFunction(casbin::ExprtkFunctionType::KeyMatch3, 2);
    evaluator.AddFunction("keyMatch3", func);
    evaluator.AddIdentifier("key1", key1);
    evaluator.AddIdentifier("key2", key2);
    evaluator.Eval("keyMatch3(key1, key2)");
    bool my_res = evaluator.GetBoolen();

    EXPECT_EQ(res, my_res);
}

TEST(TestBuiltInFunctions, TestKeyMatch3) {
    // keyMatch3() is similar with KeyMatch2(), except using "/proxy/{id}" instead of "/proxy/:id".
    TestKeyMatch3Fn("/foo", "/foo", true);
    TestKeyMatch3Fn("/foo", "/foo*", true);
    TestKeyMatch3Fn("/foo", "/foo/*", false);
    TestKeyMatch3Fn("/foo/bar", "/foo", false);
    TestKeyMatch3Fn("/foo/bar", "/foo*", false);
    TestKeyMatch3Fn("/foo/bar", "/foo/*", true);
    TestKeyMatch3Fn("/foobar", "/foo", false);
    TestKeyMatch3Fn("/foobar", "/foo*", false);
    TestKeyMatch3Fn("/foobar", "/foo/*", false);

    TestKeyMatch3Fn("/", "/{resource}", false);
    TestKeyMatch3Fn("/resource1", "/{resource}", true);
    TestKeyMatch3Fn("/myid", "/{id}/using/{resId}", false);
    TestKeyMatch3Fn("/myid/using/myresid", "/{id}/using/{resId}", true);

    TestKeyMatch3Fn("/proxy/myid", "/proxy/{id}/*", false);
    TestKeyMatch3Fn("/proxy/myid/", "/proxy/{id}/*", true);
    TestKeyMatch3Fn("/proxy/myid/res", "/proxy/{id}/*", true);
    TestKeyMatch3Fn("/proxy/myid/res/res2", "/proxy/{id}/*", true);
    TestKeyMatch3Fn("/proxy/myid/res/res2/res3", "/proxy/{id}/*", true);
    TestKeyMatch3Fn("/proxy/", "/proxy/{id}/*", false);

    TestKeyMatch3Fn("/myid/using/myresid", "/{id/using/{resId}", false);
}

void TestRegexMatchFn(std::string key1, std::string key2, bool res) {
    auto  evaluator = casbin::ExprtkEvaluator();
    auto func = casbin::ExprtkFunctionFactory::GetExprtkFunction(casbin::ExprtkFunctionType::RegexMatch, 2);
    evaluator.AddFunction("regexMatch", func);
    evaluator.AddIdentifier("key1", key1);
    evaluator.AddIdentifier("key2", key2);
    evaluator.Eval("regexMatch(key1, key2)");
    bool my_res = evaluator.GetBoolen();

    EXPECT_EQ(res, my_res);
}

TEST(TestBuiltInFunctions, TestRegexMatch) {
    TestRegexMatchFn("/topic/create", "/topic/create", true);
    TestRegexMatchFn("/topic/create/123", "/topic/create", false);
    TestRegexMatchFn("/topic/delete", "/topic/create", false);
    TestRegexMatchFn("/topic/edit", "/topic/edit/[0-9]+", false);
    TestRegexMatchFn("/topic/edit/123", "/topic/edit/[0-9]+", true);
    TestRegexMatchFn("/topic/edit/abc", "/topic/edit/[0-9]+", false);
    TestRegexMatchFn("/foo/delete/123", "/topic/delete/[0-9]+", false);
    TestRegexMatchFn("/topic/delete/0", "/topic/delete/[0-9]+", true);
    TestRegexMatchFn("/topic/edit/123s", "/topic/delete/[0-9]+", false);
}

void TestIPMatchFn(std::string ip1, std::string ip2, bool res) {
    auto  evaluator = casbin::ExprtkEvaluator();
    auto func = casbin::ExprtkFunctionFactory::GetExprtkFunction(casbin::ExprtkFunctionType::IpMatch, 2);
    evaluator.AddFunction("ipMatch", func);
    evaluator.AddIdentifier("key1", ip1);
    evaluator.AddIdentifier("key2", ip2);
    evaluator.Eval("ipMatch(key1, key2)");
    bool my_res = evaluator.GetBoolen();

    EXPECT_EQ(res, my_res);
}

TEST(TestBuiltInFunctions, TestIPMatch) {
    TestIPMatchFn("192.168.2.123", "192.168.2.0/24", true);
    TestIPMatchFn("192.168.2.123", "192.168.3.0/24", false);
    TestIPMatchFn("192.168.2.123", "192.168.2.0/16", true);
    TestIPMatchFn("192.168.2.123", "192.168.2.123/32", true);
    TestIPMatchFn("10.0.0.11", "10.0.0.0/8", true);
    TestIPMatchFn("11.0.0.123", "10.0.0.0/8", false);
}

} // namespace
