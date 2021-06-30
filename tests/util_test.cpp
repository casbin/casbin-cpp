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
* This is a test file for testing the Utility methods in casbin
*/

#include <gtest/gtest.h>
#include <casbin/casbin.h>

namespace {

void TestEscapeAssertionFn(const std::string& s, const std::string& res){
    std::string my_res = casbin::EscapeAssertion(s);
    ASSERT_EQ(my_res, res);
}

TEST(TestModel, TestEscapeAssertion) {
    TestEscapeAssertionFn("r.attr.value == p.attr", "r_attr.value == p_attr");
    TestEscapeAssertionFn("r.attp.value || p.attr", "r_attp.value || p_attr");
    TestEscapeAssertionFn("r.attp.value &&p.attr", "r_attp.value &&p_attr");
    TestEscapeAssertionFn("r.attp.value >p.attr", "r_attp.value >p_attr");
    TestEscapeAssertionFn("r.attp.value <p.attr", "r_attp.value <p_attr");
    TestEscapeAssertionFn("r.attp.value +p.attr", "r_attp.value +p_attr");
    TestEscapeAssertionFn("r.attp.value -p.attr", "r_attp.value -p_attr");
    TestEscapeAssertionFn("r.attp.value *p.attr", "r_attp.value *p_attr");
    TestEscapeAssertionFn("r.attp.value /p.attr", "r_attp.value /p_attr");
    TestEscapeAssertionFn("!r.attp.value /p.attr", "!r_attp.value /p_attr");
    TestEscapeAssertionFn("g(r.sub, p.sub) == p.attr", "g(r_sub, p_sub) == p_attr");
    TestEscapeAssertionFn("g(r.sub,p.sub) == p.attr", "g(r_sub,p_sub) == p_attr");
    TestEscapeAssertionFn("(r.attp.value || p.attr)p.u", "(r_attp.value || p_attr)p_u");
}

void TestRemoveCommentsFn(const std::string& s, const std::string& res) {
    std::string my_res = casbin::RemoveComments(s);
    ASSERT_EQ(my_res, res);
}

TEST(TestModel, TestRemoveComments) {
    TestRemoveCommentsFn("r.act == p.act # comments", "r.act == p.act");
    TestRemoveCommentsFn("r.act == p.act#comments", "r.act == p.act");
    TestRemoveCommentsFn("r.act == p.act###", "r.act == p.act");
    TestRemoveCommentsFn("### comments", "");
    TestRemoveCommentsFn("r.act == p.act", "r.act == p.act");
}

void TestArrayEqualsFn(const std::vector<std::string>& a, const std::vector<std::string>& b, bool res) {
    bool my_res = casbin::ArrayEquals(a, b);
    ASSERT_EQ(my_res, res);
}

TEST(TestModel, TestArrayEquals) {
    TestArrayEqualsFn({"a", "b", "c"}, {"a", "b", "c"}, true);
    TestArrayEqualsFn({"a", "b", "c"}, {"a", "b"}, false);
    TestArrayEqualsFn({"a", "b", "c"}, {"a", "c", "b"}, true);
    TestArrayEqualsFn({"a", "b", "c"}, {}, false);
}

} // namespace
