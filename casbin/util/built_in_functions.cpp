/*
* Copyright 2020 The casbin Authors. All Rights Reserved.
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
*/

#include "casbin/pch.h"

#ifndef BUILT_IN_FUNCTIONS_CPP
#define BUILT_IN_FUNCTIONS_CPP


#include <regex>

#include "casbin/util/built_in_functions.h"
#include "casbin/util/util.h"
#include "casbin/model/function.h"
#include "casbin/rbac/role_manager.h"
#include "casbin/exception/illegal_argument_exception.h"
#include "casbin/ip_parser/parser/CIDR.h"
#include "casbin/ip_parser/parser/IP.h"
#include "casbin/ip_parser/parser/parseCIDR.h"
#include "casbin/ip_parser/parser/parseIP.h"

namespace casbin {

// KeyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*"
ReturnType KeyMatch(Scope scope) {
    std::string key1 = GetString(scope, 0);
    std::string key2 = GetString(scope, 1);

    PushBooleanValue(scope, KeyMatch(key1, key2));
    return RETURN_RESULT;
}

bool KeyMatch(const std::string& key1, const std::string& key2) {
    size_t pos = key2.find("*");

    if (pos == std::string :: npos)
        return key1 == key2;

    if (key1.length() > pos)
        return key1.substr(0, pos) == key2.substr(0, pos);

    return key1 == key2.substr(0, pos);
}

// KeyMatch2 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource"
ReturnType KeyMatch2(Scope scope) {
    std::string key1 = GetString(scope, 0);
    std::string key2 = GetString(scope, 1);

    PushBooleanValue(scope, KeyMatch2(key1, key2));
    return RETURN_RESULT;
}

bool KeyMatch2(const std::string& key1, const std::string& key2) {
    std::vector<std::string> key1_arr = Split(key1, "/");
    std::vector<std::string> key2_arr = Split(key2, "/");

    bool res = true;
    for(int i=0;i<key2_arr.size();i++){
        if(i >= key1_arr.size()){
            res = false;
            break;
        }
        if(key1_arr[i] != key2_arr[i]){
            size_t index1 = key2_arr[i].find("*");
            size_t index2 = key2_arr[i].find(":");
            if(index1 != std::string::npos){
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

    return res;
}

// KeyMatch3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}"
ReturnType KeyMatch3(Scope scope) {
    std::string key1 = GetString(scope, 0);
    std::string key2 = GetString(scope, 1);

    PushBooleanValue(scope, KeyMatch3(key1, key2));
    return RETURN_RESULT;
}

bool KeyMatch3(const std::string& key1, const std::string& key2) {
    std::vector<std::string> key1_arr = Split(key1, "/");
    std::vector<std::string> key2_arr = Split(key2, "/");

    bool res = true;
    for(int i=0;i<key2_arr.size();i++){
        if(i >= key1_arr.size()){
            res = false;
            break;
        }
        if(key1_arr[i] != key2_arr[i]){
            size_t index1 = key2_arr[i].find("*");
            size_t index2 = key2_arr[i].find("{");
            size_t index3 = key2_arr[i].find("}");
            if(index1 != std::string::npos){
                if(index1==0){
                    res = true;
                    break;
                } else if(key1_arr[i].compare(key2_arr[i].substr(0, index1))) {
                    res = false;
                    break;
                } else
                    continue;
            }
            if(index2==0 && index3 > 0 && index3 != std::string::npos){
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

    return res;
}

// RegexMatch determines whether key1 matches the pattern of key2 in regular expression.
ReturnType RegexMatch(Scope scope) {
    std::string key1 = GetString(scope, 0);
    std::string key2 = GetString(scope, 1);

    PushBooleanValue(scope, RegexMatch(key1, key2));
    return RETURN_RESULT;
}

bool RegexMatch(const std::string& key1, const std::string& key2) {
    std::regex regex_s(key2);
    return regex_match(key1, regex_s);
}

// IPMatch determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
// For example, "192.168.2.123" matches "192.168.2.0/24"
ReturnType IPMatch(Scope scope) {
    std::string ip1 = GetString(scope, 0);
    std::string ip2 = GetString(scope, 1);

    PushBooleanValue(scope, IPMatch(ip1, ip2));
    return RETURN_RESULT;
}

bool IPMatch(const std::string& ip1, const std::string& ip2) {
    IP objIP1 = parseIP(ip1);
    if (objIP1.isLegal == false)
        throw IllegalArgumentException("invalid argument: ip1 in IPMatch() function is not an IP address.");

    CIDR objCIDR = parseCIDR(ip2);
    if (objCIDR.ip.isLegal == false) {
        IP objIP2 = parseIP(ip2);
        if (objIP2.isLegal == false)
            throw IllegalArgumentException("invalid argument: ip1 in IPMatch() function is not an IP address.");

        return objIP1.Equal(objIP2);
    }

    return objCIDR.net.contains(objIP1);
}

// GFunction is the method of the g(_, _) function.
ReturnType GFunction(Scope scope) {
    RoleManager* rm;
    rm = reinterpret_cast<RoleManager*>(GetPointer(scope, 0));
    std::string name1 = GetString(scope, 1);
    std::string name2 = GetString(scope, 2);

    int len = Size(scope);

    if(rm == NULL)
        PushBooleanValue(scope, name1 == name2);
    else if (len == 3) {
        std::vector<std::string> domain;
        bool res = rm->HasLink(name1, name2, domain);
        PushBooleanValue(scope, res);
    } else {
        std::vector<std::string> domain{GetString(scope, 3)};
        bool res = rm->HasLink(name1, name2, domain);
        PushBooleanValue(scope, res);
    }

    return RETURN_RESULT;
}

} // namespace casbin

#endif // BUILT_IN_FUNCTIONS_CPP
