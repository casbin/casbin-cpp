// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// package util

// import (
// 	"errors"
// 	"net"
// 	"regexp"
// 	"strings"

// 	"github.com/Knetic/govaluate"
// 	"github.com/casbin/casbin/v2/rbac"
// )

#ifndef CASBIN_CPP_UTIL_BUILT_IN_FUNCTIONS
#define CASBIN_CPP_UTIL_BUILT_IN_FUNCTIONS

#include <string>
#include <vector>
#include <regex>

#include "./findAllOccurences.h"
#include "../exception/IllegalArgumentException.h"
#include "../IPParser/parser/CIDR.h"
#include "../IPParser/parser/IP.h"
#include "../IPParser/parser/parseCIDR.h"
#include "../IPParser/parser/parseIP.h"

using namespace std;

// KeyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*"
bool KeyMatch(string key1, string key2) {
	size_t pos = key1.find("*");
	if(pos == string :: npos) {
		return key1 == key2;
	}

	if(key1.length() > pos) {
		return key1.substr(0, pos) == key2.substr(0, pos);
	}
	return key1 == key2.substr(0, pos);
}

// KeyMatchFunc is the wrapper for KeyMatch.
bool KeyMatchFunc(vector < string > args) {
	string name1 = args[0];
	string name2 = args[1];

	return KeyMatch(name1, name2);
}

// KeyMatch2 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource"
bool KeyMatch2(string key1, string key2) {
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
	regex regex_s1("^"+key2+"$");
	return regex_match(key1, regex_s1);
}

// KeyMatch2Func is the wrapper for KeyMatch2.
template <typename argument>
argument KeyMatch2Func(vector <argument> args) {
	string name1 = args[0];
	string name2 = args[1];

	return KeyMatch2(name1, name2);
}

// KeyMatch3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}"
bool KeyMatch3(string key1, string key2) {
	vector <size_t> indexes = findAllOccurances(key2, "/*");
	for(int i = 0 ; i < indexes.size() ; i++) {
		key1.replace(indexes[i], 2, "/.*");
	}

	regex regex_s("(.*)\{[^/]+\}(.*)");
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
	return regex_match(key1, regex_s1);
}

// KeyMatch3Func is the wrapper for KeyMatch3.
bool KeyMatch3Func(vector <string> args) {
	string name1 = args[0];
	string name2 = args[1];

	return KeyMatch3(name1, name2);
}

// KeyMatch4 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// Besides what KeyMatch3 does, KeyMatch4 can also match repeated patterns:
// "/parent/123/child/123" matches "/parent/{id}/child/{id}"
// "/parent/123/child/456" does not match "/parent/{id}/child/{id}"
// But KeyMatch3 will match both.
bool KeyMatch4(string key1, string key2) {
	// key2 = strings.Replace(key2, "/*", "/.*", -1)
	vector <size_t> indexes = findAllOccurances(key2, "/*");
	for(int i = 0 ; i < indexes.size() ; i++) {
		key1.replace(indexes[i], 2, "/.*");
	}

	tokens := []string{}
	j := -1
	for i, c := range key2 {
		if c == '{' {
			j = i
		} else if c == '}' {
			tokens = append(tokens, key2[j:i+1])
		}
	}

	re := regexp.MustCompile(`(.*)\{[^/]+\}(.*)`)
	for {
		if !strings.Contains(key2, "/{") {
			break
		}

		key2 = re.ReplaceAllString(key2, "$1([^/]+)$2")
	}

	re = regexp.MustCompile("^" + key2 + "$")
	values := re.FindStringSubmatch(key1)
	if values == nil {
		return false
	}
	values = values[1:]

	if len(tokens) != len(values) {
		panic(errors.New("KeyMatch4: number of tokens is not equal to number of values"))
	}

	m := map[string][]string{}
	for i := 0; i < len(tokens); i++ {
		if _, ok := m[tokens[i]]; !ok {
			m[tokens[i]] = []string{}
		}

		m[tokens[i]] = append(m[tokens[i]], values[i])
	}

	for _, values := range m {
		if len(values) > 1 {
			for i := 1; i < len(values); i++ {
				if values[i] != values[0] {
					return false
				}
			}
		}
	}

	return true
}

// KeyMatch4Func is the wrapper for KeyMatch4.
bool KeyMatch4Func(vector <string> args) {
	string name1 = args[0];
	string name2 = args[1];

	return KeyMatch4(name1, name2);
}

// RegexMatch determines whether key1 matches the pattern of key2 in regular expression.
bool RegexMatch(string key1, string key2) {
	regex regex_s(key2);
	return regex_match(key1, regex_s);
}

// RegexMatchFunc is the wrapper for RegexMatch.
bool RegexMatchFunc(vector <string> args) {
	string name1 = args[0];
	string name2 = args[1];

	return RegexMatch(name1, name2);
}

// IPMatch determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
// For example, "192.168.2.123" matches "192.168.2.0/24"
bool IPMatch(string ip1, string ip2) {
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

		return objIP1.Equal(objIP2);
	}

	return objCIDR.net.contains(objIP1);
}

// IPMatchFunc is the wrapper for IPMatch.
bool IPMatchFunc(vector <string> args) {
	string ip1 = args[0];
	string ip2 = args[1];

	return IPMatch(ip1, ip2);
}

// GenerateGFunction is the factory method of the g(_, _) function.
func GenerateGFunction(rm rbac.RoleManager) govaluate.ExpressionFunction {
	return func(args ...interface{}) (interface{}, error) {
		name1 := args[0].(string)
		name2 := args[1].(string)

		if rm == nil {
			return name1 == name2, nil
		} else if len(args) == 2 {
			res, _ := rm.HasLink(name1, name2)
			return res, nil
		} else {
			domain := args[2].(string)
			res, _ := rm.HasLink(name1, name2, domain)
			return res, nil
		}
	}
}

#endif