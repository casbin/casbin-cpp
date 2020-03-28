#ifndef CASBIN_CPP_UTIL_BUILT_IN_FUNCTIONS
#define CASBIN_CPP_UTIL_BUILT_IN_FUNCTIONS

#include <string>
#include <vector>
#include <regex>

#include "../rbac/RoleManager.h"
#include "../model/duktape_config.h"
#include "./findAllOccurences.h"
#include "../exception/IllegalArgumentException.h"
#include "../IPParser/parser/CIDR.h"
#include "../IPParser/parser/IP.h"
#include "../IPParser/parser/parseCIDR.h"
#include "../IPParser/parser/parseIP.h"

using namespace std;

// KeyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*"
ReturnType KeyMatch(Scope scope) {
	string key1 = getString(scope, 0);
	string key2 = getString(scope, 1);

	size_t pos = key1.find("*");

	if(pos == string :: npos) {
		pushBooleanValue(scope, key1 == key2);
		return RETURN_RESULT;
	}

	if(key1.length() > pos) {
		pushBooleanValue(scope, key1.substr(0, pos) == key2.substr(0, pos));
		return RETURN_RESULT;
	}

	pushBooleanValue(scope, key1 == key2.substr(0, pos));
	return RETURN_RESULT;
}

// KeyMatch2 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource"
ReturnType KeyMatch2(Scope scope) {
	string key1 = getString(scope, 0);
	string key2 = getString(scope, 1);

	vector <size_t> indexes = findAllOccurances(key2, "/*");
	for(int i = 0 ; i < indexes.size() ; i++) {
		key1.replace(indexes[i], 2, "/.*");
	}

	regex regex_s("(.*):[^/]+(.*)");
    smatch match;
	
	while(true) {

		if(key2.find("/:") == string::npos) {
			break;
		}

		if (regex_search(key2, match, regex_s)) {
			for (int i=1; i<match.size(); i++) {
				key2 = key2.replace(match.position(i), match.str(i).length(), "$1[^/]+$2");
			}
		}

	}

	regex regex_s1("^" + key2 + "$");
	pushBooleanValue(scope, regex_match(key1, regex_s1));
	return RETURN_RESULT;
}

// KeyMatch3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}"
ReturnType KeyMatch3(Scope scope) {
	string key1 = getString(scope, 0);
	string key2 = getString(scope, 1);

	vector <size_t> indexes = findAllOccurances(key2, "/*");
	for(int i = 0 ; i < indexes.size() ; i++) {
		key1.replace(indexes[i], 2, "/.*");
	}

	regex regex_s("(.*)\\{[^/]+\\}(.*)");
    smatch match;
	
	while(true) {
		if(key2.find("/{") == string::npos) {
			break;
		}
		if (regex_search(key2, match, regex_s)) {
			for (int i=1; i<match.size(); i++) {
				key2 = key2.replace(match.position(i), match.str(i).length(), "$1[^/]+$2");
			}
		}
	}

	regex regex_s1("^"+key2+"$");
	pushBooleanValue(scope, regex_match(key1, regex_s1));
	return RETURN_RESULT;
}

// RegexMatch determines whether key1 matches the pattern of key2 in regular expression.
ReturnType RegexMatch(Scope scope) {
	string key1 = getString(scope, 0);
	string key2 = getString(scope, 1);

	regex regex_s(key2);
	pushBooleanValue(scope, regex_match(key1, regex_s));
	return RETURN_RESULT;
}

// IPMatch determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
// For example, "192.168.2.123" matches "192.168.2.0/24"
ReturnType IPMatch(Scope scope) {
	string ip1 = getString(scope, 0);
	string ip2 = getString(scope, 1);

	IP objIP1 = parseIP(ip1);
	if(objIP1.isLegal == false) {
		IllegalArgumentException("invalid argument: ip1 in IPMatch() function is not an IP address.");
	}

	CIDR objCIDR = parseCIDR(ip2);
	if(objCIDR.ip.isLegal == false) {
		IP objIP2 = parseIP(ip2);
		if(objIP2.isLegal == false) {
			IllegalArgumentException("invalid argument: ip1 in IPMatch() function is not an IP address.");
		}

		pushBooleanValue(scope, objIP1.Equal(objIP2));
		return RETURN_RESULT;
	}

	pushBooleanValue(scope, objCIDR.net.contains(objIP1));
	return RETURN_RESULT;
}

// GFunction is the method of the g(_, _) function.
ReturnType GFunction(Scope scope) {
	string name1 = getString(scope, 0);
	string name2 = getString(scope, 1);

	int len = size(scope);

	fetchIdentifier(scope, "rm");

	RoleManager *rm;
	rm = (RoleManager *)getPointer(scope);

	if(rm == NULL) {
		duk_push_boolean(scope, name1 == name2);
	} else if(len == 2) {
		vector <string> domain;
		bool res = rm->hasLink(name1, name2, domain);
		duk_push_boolean(scope, res);
	} else {
		vector <string> domain{getString(scope, 2)};
		bool res = rm->hasLink(name1, name2, domain);
		duk_push_boolean(scope, res);
	}

	return RETURN_RESULT;
}

#endif