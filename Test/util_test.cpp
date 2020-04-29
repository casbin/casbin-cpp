#include "pch.h"
#include "../casbin/util/util.h"

TEST(UtilTest, EscapeAssertionTest) {
	EXPECT_EQ(Util::EscapeAssertion("r.attr.value == p.attr"), "r_attr.value == p_attr");
	EXPECT_EQ(Util::EscapeAssertion("r.attp.value || p.attr"), "r_attp.value || p_attr");
	EXPECT_EQ(Util::EscapeAssertion("r.attp.value &&p.attr"), "r_attp.value &&p_attr");
	EXPECT_EQ(Util::EscapeAssertion("r.attp.value >p.attr"), "r_attp.value >p_attr");
	EXPECT_EQ(Util::EscapeAssertion("r.attp.value +p.attr"), "r_attp.value +p_attr");
	EXPECT_EQ(Util::EscapeAssertion("r.attp.value -p.attr"), "r_attp.value -p_attr");
	EXPECT_EQ(Util::EscapeAssertion("r.attp.value *p.attr"), "r_attp.value *p_attr");
	EXPECT_EQ(Util::EscapeAssertion("r.attp.value /p.attr"), "r_attp.value /p_attr");
	EXPECT_EQ(Util::EscapeAssertion("!r.attp.value /p.attr"), "!r_attp.value /p_attr");
	EXPECT_EQ(Util::EscapeAssertion("g(r.sub, p.sub) == p.attr"), "g(r_sub, p_sub) == p_attr");
	EXPECT_EQ(Util::EscapeAssertion("g(r.sub,p.sub) == p.attr"), "g(r_sub,p_sub) == p_attr");
	EXPECT_EQ(Util::EscapeAssertion("(r.attp.value || p.attr)p.u"), "(r_attp.value || p_attr)p_u");
}

TEST(UtilTest, RemoveComments) {
	EXPECT_EQ(Util::RemoveComments("r.act == p.act # comments"), "r.act == p.act");
	EXPECT_EQ(Util::RemoveComments("r.act == p.act#comments"), "r.act == p.act");
	EXPECT_EQ(Util::RemoveComments("r.act == p.act###"), "r.act == p.act");
	EXPECT_EQ(Util::RemoveComments("### comments"), "");
	EXPECT_EQ(Util::RemoveComments("r.act == p.act"), "r.act == p.act");
}

TEST(UtilTest, ArrayEquals) {

	EXPECT_EQ(Util::ArrayEquals({ "a", "b", "c" }, { "a", "b", "c" }),true);
	EXPECT_EQ(Util::ArrayEquals({ "a", "b", "c" }, { "a", "b"}), false);
	EXPECT_EQ(Util::ArrayEquals({ "a", "b", "c" }, { "a", "c", "b" }), false);
	EXPECT_EQ(Util::ArrayEquals({ "a", "b", "c" }, {}), false);
}

TEST(UtilTest, Array2DEquals) {
	EXPECT_EQ(Util::Array2DEquals({ {"a", "b", "c"}, {"1", "2", "3"} }, { {"a", "b", "c"}, {"1", "2", "3"} }), true);
	EXPECT_EQ(Util::Array2DEquals({ {"a", "b", "c"}, {"1", "2", "3"} }, { {"a", "b", "c"} }), false);
	EXPECT_EQ(Util::Array2DEquals({ {"a", "b", "c"}, {"1", "2", "3"} }, { {"a", "b", "c"}, {"1", "2"} }), false);
	EXPECT_EQ(Util::Array2DEquals({ {"a", "b", "c"}, {"1", "2", "3"} }, { {"1", "2", "3"}, {"a", "b", "c"} }), false);
	EXPECT_EQ(Util::Array2DEquals({ {"a", "b", "c"}, {"1", "2", "3"} }, { }), false);
}

TEST(UtilTest, SetEquals) {
	EXPECT_EQ(Util::SetEquals({ "a", "b", "c" }, { "a", "b", "c" }), true);
	EXPECT_EQ(Util::SetEquals({ "a", "b", "c" }, { "a", "b"}), false);
	EXPECT_EQ(Util::SetEquals({ "a", "b", "c" }, { "a", "c", "b" }), true);
	EXPECT_EQ(Util::SetEquals({ "a", "b", "c" }, {}), false);
}