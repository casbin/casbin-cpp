#include "pch.h"
#include "../casbin/util/builtin_operators.h"

void testKeyMatch(string key1, string key2, bool res) {
	bool myRes = BuiltinOperators::KeyMatch(key1, key2);
	EXPECT_EQ(myRes,res);
};

void testKeyMatch2(string key1, string key2, bool res) {
	bool myRes = BuiltinOperators::KeyMatch2(key1, key2);
	EXPECT_EQ(myRes, res);
};

void testKeyMatch3(string key1, string key2, bool res) {
	bool myRes = BuiltinOperators::KeyMatch3(key1, key2);
	EXPECT_EQ(myRes, res);
};

void testKeyMatch4(string key1, string key2, bool res) {
	bool myRes = BuiltinOperators::KeyMatch4(key1, key2);
	EXPECT_EQ(myRes, res);
};

void testRegexMatch(string key1, string key2, bool res) {
	bool myRes = BuiltinOperators::RegexMatch(key1, key2);
	EXPECT_EQ(myRes, res);
};

void testIPMatch(string key1, string key2, bool res) {
	bool myRes = BuiltinOperators::IPMatch(key1, key2);
	EXPECT_EQ(myRes, res);
};

TEST(BuiltinOperatorsTest, KeyMatch1Test) {
	testKeyMatch("/foo", "/foo", true);
	testKeyMatch("/foo", "/foo*", true);
	testKeyMatch("/foo", "/foo/*", false);
	testKeyMatch( "/foo/bar", "/foo", false);
	testKeyMatch("/foo/bar", "/foo*", true);
	testKeyMatch( "/foo/bar", "/foo/*", true);
	testKeyMatch("/foobar", "/foo", false);
	testKeyMatch("/foobar", "/foo*", true);
	testKeyMatch( "/foobar", "/foo/*", false);
}

TEST(BuiltinOperatorsTest, KeyMatch2Test) {
	testKeyMatch2( "/foo", "/foo", true);
	testKeyMatch2( "/foo", "/foo*", true);
	testKeyMatch2( "/foo", "/foo/*", false);
	testKeyMatch2( "/foo/bar", "/foo", false);
	testKeyMatch2( "/foo/bar", "/foo*", false); // different with KeyMatch.
	testKeyMatch2( "/foo/bar", "/foo/*", true);
	testKeyMatch2( "/foobar", "/foo", false);
	testKeyMatch2( "/foobar", "/foo*", false);// different with KeyMatch.
	testKeyMatch2( "/foobar", "/foo/*", false);

	testKeyMatch2( "/", "/:resource", false);
	testKeyMatch2( "/resource1", "/:resource", true);
	testKeyMatch2( "/myid", "/:id/using/:resId", false);
	testKeyMatch2( "/myid/using/myresid", "/:id/using/:resId", true);

	testKeyMatch2( "/proxy/myid", "/proxy/:id/*", false);
	testKeyMatch2( "/proxy/myid/", "/proxy/:id/*", true);
	testKeyMatch2( "/proxy/myid/res", "/proxy/:id/*", true);
	testKeyMatch2( "/proxy/myid/res/res2", "/proxy/:id/*", true);
	testKeyMatch2( "/proxy/myid/res/res2/res3", "/proxy/:id/*", true);
	testKeyMatch2( "/proxy/", "/proxy/:id/*", false);

	testKeyMatch2( "/alice", "/:id", true);
	testKeyMatch2( "/alice/all", "/:id/all", true);
	testKeyMatch2( "/alice", "/:id/all", false);
	testKeyMatch2("/alice/all", "/:id", false);
}

TEST(BuiltinOperatorsTest, KeyMatch3Test) {
	// keyMatch3() is similar with KeyMatch2(), except using "/proxy/{id}" instead of "/proxy/:id".
	testKeyMatch3(  "/foo", "/foo", true);
	testKeyMatch3(  "/foo", "/foo*", true);
	testKeyMatch3(  "/foo", "/foo/*", false);
	testKeyMatch3(  "/foo/bar", "/foo", false);
	testKeyMatch3(  "/foo/bar", "/foo*", false);
	testKeyMatch3(  "/foo/bar", "/foo/*", true);
	testKeyMatch3(  "/foobar", "/foo", false);
	testKeyMatch3(  "/foobar", "/foo*", false);
	testKeyMatch3(  "/foobar", "/foo/*", false);

	testKeyMatch3(  "/", "/{resource}", false);
	testKeyMatch3(  "/resource1", "/{resource}", true);
	testKeyMatch3(  "/myid", "/{id}/using/{resId}", false);
	testKeyMatch3(  "/myid/using/myresid", "/{id}/using/{resId}", true);

	testKeyMatch3(  "/proxy/myid", "/proxy/{id}/*", false);
	testKeyMatch3(  "/proxy/myid/", "/proxy/{id}/*", true);
	testKeyMatch3(  "/proxy/myid/res", "/proxy/{id}/*", true);
	testKeyMatch3(  "/proxy/myid/res/res2", "/proxy/{id}/*", true);
	testKeyMatch3(  "/proxy/myid/res/res2/res3", "/proxy/{id}/*", true);
	testKeyMatch3(  "/proxy/", "/proxy/{id}/*", false);
}

TEST(BuiltinOperatorsTest, KeyMatch4Test) {
	testKeyMatch4(  "/parent/123/child/123", "/parent/{id}/child/{id}", true);
	testKeyMatch4(  "/parent/123/child/456", "/parent/{id}/child/{id}", false);

	testKeyMatch4(  "/parent/123/child/123", "/parent/{id}/child/{another_id}", true);
	testKeyMatch4(  "/parent/123/child/456", "/parent/{id}/child/{another_id}", true);

	testKeyMatch4(  "/parent/123/child/123/book/123", "/parent/{id}/child/{id}/book/{id}", true);
	testKeyMatch4(  "/parent/123/child/123/book/456", "/parent/{id}/child/{id}/book/{id}", false);
	testKeyMatch4(  "/parent/123/child/456/book/123", "/parent/{id}/child/{id}/book/{id}", false);
	testKeyMatch4(  "/parent/123/child/456/book/", "/parent/{id}/child/{id}/book/{id}", false);
	testKeyMatch4(  "/parent/123/child/456", "/parent/{id}/child/{id}/book/{id}", false);
}

TEST(BuiltinOperatorsTest, RegexMatchTest) {
	testRegexMatch(  "/topic/create", "/topic/create", true);
	testRegexMatch(  "/topic/create/123", "/topic/create", true);
	testRegexMatch(  "/topic/delete", "/topic/create", false);
	testRegexMatch(  "/topic/edit", "/topic/edit/[0-9]+", false);
	testRegexMatch(  "/topic/edit/123", "/topic/edit/[0-9]+", true);
	testRegexMatch(  "/topic/edit/abc", "/topic/edit/[0-9]+", false);
	testRegexMatch(  "/foo/delete/123", "/topic/delete/[0-9]+", false);
	testRegexMatch(  "/topic/delete/0", "/topic/delete/[0-9]+", true);
	testRegexMatch(  "/topic/edit/123s", "/topic/delete/[0-9]+", false);
}

TEST(BuiltinOperatorsTest, IPMatchTest) {
	testIPMatch(  "192.168.2.123", "192.168.2.0/24", true);
	testIPMatch(  "192.168.2.123", "192.168.3.0/24", false);
	testIPMatch(  "192.168.2.123", "192.168.2.0/16", true);
	testIPMatch(  "192.168.2.123", "192.168.2.123", true);
	testIPMatch(  "192.168.2.123", "192.168.2.123/32", true);
	testIPMatch(  "10.0.0.11", "10.0.0.0/8", true);
	testIPMatch(  "11.0.0.123", "10.0.0.0/8", false);
}