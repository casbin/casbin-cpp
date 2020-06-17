#pragma once

#include "pch.h"

#include <util.h>

using namespace std;

class TestUtil : public ::testing::Test {

};

void TestEscapeAssertion(string s, string res) {
    string my_res = EscapeAssertion(s);
    EXPECT_EQ(my_res, res);
}

TEST_F(TestUtil, TestEscapeAssertion) {
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
    EXPECT_EQ(my_res, res);
}

TEST_F(TestUtil, TestRemoveComments) {
    TestRemoveComments("r.act == p.act # comments", "r.act == p.act");
    TestRemoveComments("r.act == p.act#comments", "r.act == p.act");
    TestRemoveComments("r.act == p.act###", "r.act == p.act");
    TestRemoveComments("### comments", "");
    TestRemoveComments("r.act == p.act", "r.act == p.act");
}

void TestArrayEquals(vector<string> a, vector<string> b, bool res) {
    bool my_res = ArrayEquals(a, b);
    EXPECT_EQ(my_res, res);
}

TEST_F(TestUtil, TestArrayEquals) {
    TestArrayEquals(vector<string> {"a", "b", "c"}, vector<string> {"a", "b", "c"}, true);
    TestArrayEquals(vector<string> {"a", "b", "c"}, vector<string> {"a", "b"}, false);
    TestArrayEquals(vector<string> {"a", "b", "c"}, vector<string> {"a", "c", "b"}, false);
    TestArrayEquals(vector<string> {"a", "b", "c"}, vector<string> {}, false);
}