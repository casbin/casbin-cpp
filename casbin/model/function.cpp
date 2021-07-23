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

#include "pch.h"

#ifndef FUNCTION_CPP
#define FUNCTION_CPP


#include "./function.h"
#include "../util/util.h"

namespace casbin {

FunctionMap::FunctionMap(){
    scope = NULL;
}

void FunctionMap::ProcessFunctions(const std::string& expression){
    for(const std::string& func: func_list) {
        size_t index = expression.find(func+"(");

        if (index != std::string::npos) {
            size_t close_index = expression.find(")", index);
            size_t start = index + func.length() + 1;

            std::string function_params = expression.substr(start, close_index - start);
            FetchIdentifier(this->scope, func);
            std::vector<std::string> params = Split(function_params, ",");

            for(std::string& param : params) {
                size_t quote_index = param.find("\"");

                if (quote_index == std::string::npos)
                    Get(this->scope, Trim(param));

                else {
                    param = param.replace(quote_index, 1, "'");
                    size_t second_quote_index = param.find("\"", quote_index + 1);
                    param = param.replace(second_quote_index, 1, "'");
                    Get(this->scope, Trim(param));
                }
            }
        }
    }
}

int FunctionMap::GetRLen(){
    bool found = FetchIdentifier(scope, "rlen");
    if(found)
        return GetInt(scope);
    return -1;
}

bool FunctionMap::Evaluate(const std::string& expression){
    ProcessFunctions(expression);
    return Eval(scope, expression);
}

bool FunctionMap::GetBooleanResult() {
    return static_cast<bool>(duk_get_boolean(scope, -1));
}

// AddFunction adds an expression function.
void FunctionMap::AddFunction(const std::string& func_name, Function f, Index nargs) {
    func_list.push_back(func_name);
    PushFunction(scope, f, func_name, nargs);
}

void FunctionMap::AddFunctionPropToR(const std::string& identifier, Function func, Index nargs){
    PushFunctionPropToObject(scope, "r", func, identifier, nargs);
}

void FunctionMap::AddBooleanPropToR(const std::string& identifier, bool val){
    PushBooleanPropToObject(scope, "r", val, identifier);
}

void FunctionMap::AddTruePropToR(const std::string& identifier){
    PushTruePropToObject(scope, "r", identifier);
}

void FunctionMap::AddFalsePropToR(const std::string& identifier){
    PushFalsePropToObject(scope, "r", identifier);
}

void FunctionMap::AddIntPropToR(const std::string& identifier, int val){
    PushIntPropToObject(scope, "r", val, identifier);
}

void FunctionMap::AddFloatPropToR(const std::string& identifier, float val){
    PushFloatPropToObject(scope, "r", val, identifier);
}

void FunctionMap::AddDoublePropToR(const std::string& identifier, double val){
    PushDoublePropToObject(scope, "r", val, identifier);
}

void FunctionMap::AddStringPropToR(const std::string& identifier, const std::string& val){
    PushStringPropToObject(scope, "r", val, identifier);
}

void FunctionMap::AddPointerPropToR(const std::string& identifier, void* val){
    PushPointerPropToObject(scope, "r", val, identifier);
}

void FunctionMap::AddObjectPropToR(const std::string& identifier){
    PushObjectPropToObject(scope, "r", identifier);
}

// LoadFunctionMap loads an initial function map.
void FunctionMap::LoadFunctionMap() {
    AddFunction("keyMatch", KeyMatch, 2);
    AddFunction("keyMatch2", KeyMatch2, 2);
    AddFunction("keyMatch3", KeyMatch3, 2);
    AddFunction("regexMatch", RegexMatch, 2);
    AddFunction("ipMatch", IPMatch, 2);
}

} // namespace casbin

#endif // FUNCTION_CPP
