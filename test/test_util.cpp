#include "pch.h"

#ifndef TEST_UTIL_CPP
#define TEST_UTIL_CPP


#include <util.h>

namespace test_util
{
    using namespace casbin;

    TEST_CLASS(TestModel)
    {
        public:

            void TestEscapeAssertion(std::string s, std::string res){
                std::string my_res = EscapeAssertion(s);
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

            void TestRemoveComments(std::string s, std::string res) {
                std::string my_res = RemoveComments(s);
                Assert::AreEqual(my_res, res);
            }

            TEST_METHOD(TestRemoveComments) {
                TestRemoveComments("r.act == p.act # comments", "r.act == p.act");
                TestRemoveComments("r.act == p.act#comments", "r.act == p.act");
                TestRemoveComments("r.act == p.act###", "r.act == p.act");
                TestRemoveComments("### comments", "");
                TestRemoveComments("r.act == p.act", "r.act == p.act");
            }

            void TestArrayEquals(std::vector<std::string> a, std::vector<std::string> b, bool res) {
                bool my_res = ArrayEquals(a, b);
                Assert::AreEqual(my_res, res);
            }

            TEST_METHOD(TestArrayEquals) {
                TestArrayEquals(std::vector<std::string>{"a", "b", "c"}, std::vector<std::string>{"a", "b", "c"}, true);
                TestArrayEquals(std::vector<std::string>{"a", "b", "c"}, std::vector<std::string>{"a", "b"}, false);
                TestArrayEquals(std::vector<std::string>{"a", "b", "c"}, std::vector<std::string>{"a", "c", "b"}, true);
                TestArrayEquals(std::vector<std::string>{"a", "b", "c"}, std::vector<std::string>{}, false);
            }
    };
}

#endif // TEST_UTIL_CPP
