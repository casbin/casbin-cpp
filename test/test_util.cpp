#pragma once

#include "pch.h"

#include <util.h>

using namespace std;

namespace test_util
{
    TEST_CLASS(TestModel)
    {
        public:

            void TestEscapeAssertion(string s, string res) {
                string my_res = EscapeAssertion(s);
                Assert::AreEqual(my_res, res);
            }

            TEST_METHOD(TestEscapeAssertion) {
                TestEscapeAssertion("r.attr.value == p.attr", "r_attr.value == p_attr");
                TestEscapeAssertion("r.attp.value || p.attr", "r_attp.value || p_attr");
                TestEscapeAssertion("r.attp.value &&p.attr", "r_attp.value &&p_attr");
                TestEscapeAssertion("r.attp.value >p.attr", "r_attp.value >p_attr");
                TestEscapeAssertion("r.attp.value <p.attr", "r_attp.value <p_attr");
                TestEscapeAssertion("r.attp.value +p.attr", "r_attp.value +p_attr");
                TestEscapeAssertion("r.attp.value -p.attr", "r_attp.value -p_attr");
                TestEscapeAssertion("r.attp.value *p.attr", "r_attp.value *p_attr");
                TestEscapeAssertion("r.attp.value /p.attr", "r_attp.value /p_attr");
                TestEscapeAssertion("!r.attp.value /p.attr", "!r_attp.value /p_attr");
                TestEscapeAssertion("g(r.sub, p.sub) == p.attr", "g(r_sub, p_sub) == p_attr");
                TestEscapeAssertion("g(r.sub,p.sub) == p.attr", "g(r_sub,p_sub) == p_attr");
                TestEscapeAssertion("(r.attp.value || p.attr)p.u", "(r_attp.value || p_attr)p_u");
            }

            void TestRemoveComments(string s, string res) {
                string my_res = RemoveComments(s);
                Assert::AreEqual(my_res, res);
            }

            TEST_METHOD(TestRemoveComments) {
                TestRemoveComments("r.act == p.act # comments", "r.act == p.act");
                TestRemoveComments("r.act == p.act#comments", "r.act == p.act");
                TestRemoveComments("r.act == p.act###", "r.act == p.act");
                TestRemoveComments("### comments", "");
                TestRemoveComments("r.act == p.act", "r.act == p.act");
            }

            void TestArrayEquals(vector<string> a, vector<string> b, bool res) {
                bool my_res = ArrayEquals(a, b);
                Assert::AreEqual(my_res, res);
            }

            TEST_METHOD(TestArrayEquals) {
                TestArrayEquals(vector<string> {"a", "b", "c"}, vector<string> {"a", "b", "c"}, true);
                TestArrayEquals(vector<string> {"a", "b", "c"}, vector<string> {"a", "b"}, false);
                TestArrayEquals(vector<string> {"a", "b", "c"}, vector<string> {"a", "c", "b"}, false);
                TestArrayEquals(vector<string> {"a", "b", "c"}, vector<string> {}, false);
            }
    };
}