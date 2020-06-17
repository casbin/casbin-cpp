#pragma once

#include "pch.h"

#include <regex>

#include "./built_in_functions.h"
#include "../rbac/role_manager.h"
#include "./util.h"
#include "../exception/illegal_argument_exception.h"
#include "../ip_parser/parser/CIDR.h"
#include "../ip_parser/parser/IP.h"
#include "../ip_parser/parser/parseCIDR.h"
#include "../ip_parser/parser/parseIP.h"

using namespace std;

// KeyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*"
ReturnType KeyMatch(Scope scope) {
    string key1 = GetString(scope, 0);
    string key2 = GetString(scope, 1);

    size_t pos = key2.find("*");

    if (pos == string :: npos) {
        PushBooleanValue(scope, key1 == key2);
        return RETURN_RESULT;
    }

    if (key1.length() > pos) {
        PushBooleanValue(scope, key1.substr(0, pos) == key2.substr(0, pos));
        return RETURN_RESULT;
    }

    PushBooleanValue(scope, key1 == key2.substr(0, pos));
    return RETURN_RESULT;
}

// KeyMatch2 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource"
ReturnType KeyMatch2(Scope scope) {
    string key1 = GetString(scope, 0);
    string key2 = GetString(scope, 1);

    vector <size_t> indexes = FindAllOccurences(key2, "/*");
    for (int i = 0 ; i < indexes.size() ; i++) {
        key1.replace(indexes[i], 2, "/.*");
    }

    regex regex_s("(.*):[^/]+(.*)");
    smatch match;

    while (true) {

        if (key2.find("/:") == string::npos)
            break;

        if (regex_search(key2, match, regex_s)) {
            for (int i=1; i<match.size(); i++)
                key2 = key2.replace(match.position(i), match.str(i).length(), "$1[^/]+$2");
        }

    }

    regex regex_s1("^" + key2 + "$");
    PushBooleanValue(scope, regex_match(key1, regex_s1));
    return RETURN_RESULT;
}

// KeyMatch3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}"
ReturnType KeyMatch3(Scope scope) {
    string key1 = GetString(scope, 0);
    string key2 = GetString(scope, 1);

    vector<size_t> indexes = FindAllOccurences(key2, "/*");
    for (int i = 0 ; i < indexes.size() ; i++)
        key1.replace(indexes[i], 2, "/.*");

    regex regex_s("(.*)\\{[^/]+\\}(.*)");
    smatch match;

    while (true) {
        if (key2.find("/{") == string::npos)
            break;

        if (regex_search(key2, match, regex_s)) {
            for (int i=1; i<match.size(); i++)
                key2 = key2.replace(match.position(i), match.str(i).length(), "$1[^/]+$2");
        }
    }

    regex regex_s1("^"+key2+"$");
    PushBooleanValue(scope, regex_match(key1, regex_s1));
    return RETURN_RESULT;
}

// RegexMatch determines whether key1 matches the pattern of key2 in regular expression.
ReturnType RegexMatch(Scope scope) {
    string key1 = GetString(scope, 0);
    string key2 = GetString(scope, 1);

    regex regex_s(key2);
    PushBooleanValue(scope, regex_match(key1, regex_s));
    return RETURN_RESULT;
}

// IPMatch determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
// For example, "192.168.2.123" matches "192.168.2.0/24"
ReturnType IPMatch(Scope scope) {
    string ip1 = GetString(scope, 0);
    string ip2 = GetString(scope, 1);

    IP objIP1 = parseIP(ip1);
    if (objIP1.isLegal == false)
        IllegalArgumentException("invalid argument: ip1 in IPMatch() function is not an IP address.");

    CIDR objCIDR = parseCIDR(ip2);
    if (objCIDR.ip.isLegal == false) {
        IP objIP2 = parseIP(ip2);
        if (objIP2.isLegal == false)
            IllegalArgumentException("invalid argument: ip1 in IPMatch() function is not an IP address.");

        PushBooleanValue(scope, objIP1.Equal(objIP2));
        return RETURN_RESULT;
    }

    PushBooleanValue(scope, objCIDR.net.contains(objIP1));
    return RETURN_RESULT;
}

// GFunction is the method of the g(_, _) function.
ReturnType GFunction(Scope scope) {
    RoleManager *rm;
    rm = (RoleManager*)GetPointer(scope, 0);
    string name1 = GetString(scope, 1);
    string name2 = GetString(scope, 2);

    int len = Size(scope);

    if(rm == NULL)
        PushBooleanValue(scope, name1 == name2);
    else if (len == 2) {
        vector<string> domain;
        bool res = rm->HasLink(name1, name2, domain);
        PushBooleanValue(scope, res);
    } else {
        vector<string> domain{GetString(scope, 2)};
        bool res = rm->HasLink(name1, name2, domain);
        PushBooleanValue(scope, res);
    }

    return RETURN_RESULT;
}