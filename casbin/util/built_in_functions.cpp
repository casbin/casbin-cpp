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

    vector<string> key1_arr = Split(key1, "/");
    vector<string> key2_arr = Split(key2, "/");

    bool res = true;
    for(int i=0;i<key2_arr.size();i++){
        if(i >= key1_arr.size()){
            res = false;
            break;
        }
        if(key1_arr[i] != key2_arr[i]){
            int index1 = key2_arr[i].find("*");
            int index2 = key2_arr[i].find(":");
            if(index1 != string::npos){
                if(index1==0){
                    res = true;
                    break;
                } else if(key1_arr[i].compare(key2_arr[i].substr(0, index1))) {
                    res = false;
                    break;
                } else
                    continue;
            }
            if(index2==0){
                if(key1_arr[i]=="" || !key2_arr[i].substr(1).compare("")){
                    res = false;
                    break;
                }
                else
                    continue;
            }
            res = false;
            break;
        }else
            continue;
    }

    if(key2_arr.size() < key1_arr.size())
        if(key2_arr[key2_arr.size()-1] != "*")
            res = false;

    PushBooleanValue(scope, res);
    return RETURN_RESULT;
}

// KeyMatch3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}"
ReturnType KeyMatch3(Scope scope) {
    string key1 = GetString(scope, 0);
    string key2 = GetString(scope, 1);

    vector<string> key1_arr = Split(key1, "/");
    vector<string> key2_arr = Split(key2, "/");

    bool res = true;
    for(int i=0;i<key2_arr.size();i++){
        if(i >= key1_arr.size()){
            res = false;
            break;
        }
        if(key1_arr[i] != key2_arr[i]){
            int index1 = key2_arr[i].find("*");
            int index2 = key2_arr[i].find("{");
            int index3 = key2_arr[i].find("}");
            if(index1 != string::npos){
                if(index1==0){
                    res = true;
                    break;
                } else if(key1_arr[i].compare(key2_arr[i].substr(0, index1))) {
                    res = false;
                    break;
                } else
                    continue;
            }
            if(index2==0 && index3 > 0 && index3 != string::npos){
                if(key1_arr[i]=="" || !key2_arr[i].substr(1, key2_arr[i].length()-2).compare("")){
                    res = false;
                    break;
                }
                else
                    continue;
            }
            res = false;
            break;
        }else
            continue;
    }

    if(key2_arr.size() < key1_arr.size())
        if(key2_arr[key2_arr.size()-1] != "*")
            res = false;

    PushBooleanValue(scope, res);
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
        throw IllegalArgumentException("invalid argument: ip1 in IPMatch() function is not an IP address.");

    CIDR objCIDR = parseCIDR(ip2);
    if (objCIDR.ip.isLegal == false) {
        IP objIP2 = parseIP(ip2);
        if (objIP2.isLegal == false)
            throw IllegalArgumentException("invalid argument: ip1 in IPMatch() function is not an IP address.");

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