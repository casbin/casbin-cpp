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

FunctionMap :: FunctionMap(){
    scope = nullptr;
}

void FunctionMap :: ProcessFunctions(string expression){
    for(auto func: func_list){
        auto index = expression.find(func+"(");

        if(index != string::npos){
            auto close_index = expression.find(")", index);
            auto start = index + (func+"(").length();

            string function_params = expression.substr(start, close_index-start);
            FetchIdentifier(this->scope, func);
            vector<string> params = Split(function_params, ",");

            for(auto i=0;i<params.size();i++){
                auto quote_index = params[i].find("\"");
                if(quote_index == string::npos)
                    Get(this->scope, Trim(params[i]));
                else{
                    params[i] = params[i].replace(quote_index, 1, "'");
                    auto second_quote_index = params[i].find("\"", quote_index+1);
                    params[i] = params[i].replace(second_quote_index, 1, "'");
                    Get(this->scope, Trim(params[i]));
                }
            }
        }
    }
}

int FunctionMap :: GetRLen(){
    bool found = FetchIdentifier(scope, "rlen");
    if(found)
        return GetInt(scope);
    return -1;
}

bool FunctionMap :: Evaluate(string& expression){
    ProcessFunctions(expression);
    return Eval(scope, expression);
}

bool FunctionMap :: GetBooleanResult(){
    return bool(duk_get_boolean(scope, -1));
}

// AddFunction adds an expression function.
void FunctionMap :: AddFunction(const string& func_name, Function f, Index nargs) {
    func_list.push_back(func_name);
    PushFunction(scope, f, func_name, nargs);
}

void FunctionMap :: AddFunctionPropToR(string& identifier, Function func, Index nargs){
    PushFunctionPropToObject(scope, "r", func, identifier, nargs);
}

void FunctionMap :: AddBooleanPropToR(string& identifier, bool val){
    PushBooleanPropToObject(scope, "r", val, identifier);
}

void FunctionMap :: AddTruePropToR(string& identifier){
    PushTruePropToObject(scope, "r", identifier);
}

void FunctionMap :: AddFalsePropToR(string& identifier){
    PushFalsePropToObject(scope, "r", identifier);
}

void FunctionMap :: AddIntPropToR(string& identifier, int val){
    PushIntPropToObject(scope, "r", val, identifier);
}

void FunctionMap :: AddFloatPropToR(string& identifier, float val){
    PushFloatPropToObject(scope, "r", val, identifier);
}

void FunctionMap :: AddDoublePropToR(string& identifier, double val){
    PushDoublePropToObject(scope, "r", val, identifier);
}

void FunctionMap :: AddStringPropToR(string& identifier, string& val){
    PushStringPropToObject(scope, "r", val, identifier);
}

void FunctionMap :: AddPointerPropToR(string& identifier, void* val){
    PushPointerPropToObject(scope, "r", val, identifier);
}

void FunctionMap :: AddObjectPropToR(string& identifier){
    PushObjectPropToObject(scope, "r", identifier);
}

// LoadFunctionMap loads an initial function map.
void FunctionMap :: LoadFunctionMap() {
    AddFunction("keyMatch", KeyMatch, 2);
    AddFunction("keyMatch2", KeyMatch2, 2);
    AddFunction("keyMatch3", KeyMatch3, 2);
    AddFunction("regexMatch", RegexMatch, 2);
    AddFunction("ipMatch", IPMatch, 2);
}

#endif // FUNCTION_CPP
