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

FunctionMap :: FunctionMap(){
    scope = NULL;
}

void FunctionMap :: ProcessFunctions(std::string expression){
    for(auto func: func_list){
        int index = int(expression.find(func+"("));

        if (index != std::string::npos) {
            int close_index = int(expression.find(")", index));
            int start = index + int((func+"(").length());

            std::string function_params = expression.substr(start, close_index - start);
            FetchIdentifier(this->scope, func);
            std::vector<std::string> params = Split(function_params, ",");

            for(int i=0;i<params.size();i++){
                int quote_index = int(params[i].find("\""));
                if (quote_index == std::string::npos)
                    Get(this->scope, Trim(params[i]));
                else{
                    params[i] = params[i].replace(quote_index, 1, "'");
                    int second_quote_index = int(params[i].find("\"", quote_index+1));
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

bool FunctionMap :: Evaluate(std::string expression){
    ProcessFunctions(expression);
    return Eval(scope, expression);
}

bool FunctionMap :: GetBooleanResult(){
    return bool(duk_get_boolean(scope, -1));
}

// AddFunction adds an expression function.
void FunctionMap :: AddFunction(std::string func_name, Function f, Index nargs) {
    func_list.push_back(func_name);
    PushFunction(scope, f, func_name, nargs);
}

void FunctionMap :: AddFunctionPropToR(std::string identifier, Function func, Index nargs){
    PushFunctionPropToObject(scope, "r", func, identifier, nargs);
}

void FunctionMap :: AddBooleanPropToR(std::string identifier, bool val){
    PushBooleanPropToObject(scope, "r", val, identifier);
}

void FunctionMap :: AddTruePropToR(std::string identifier){
    PushTruePropToObject(scope, "r", identifier);
}

void FunctionMap :: AddFalsePropToR(std::string identifier){
    PushFalsePropToObject(scope, "r", identifier);
}

void FunctionMap :: AddIntPropToR(std::string identifier, int val){
    PushIntPropToObject(scope, "r", val, identifier);
}

void FunctionMap :: AddFloatPropToR(std::string identifier, float val){
    PushFloatPropToObject(scope, "r", val, identifier);
}

void FunctionMap :: AddDoublePropToR(std::string identifier, double val){
    PushDoublePropToObject(scope, "r", val, identifier);
}

void FunctionMap :: AddStringPropToR(std::string identifier, std::string val){
    PushStringPropToObject(scope, "r", val, identifier);
}

void FunctionMap :: AddPointerPropToR(std::string identifier, void* val){
    PushPointerPropToObject(scope, "r", val, identifier);
}

void FunctionMap :: AddObjectPropToR(std::string identifier){
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

} // namespace casbin

#endif // FUNCTION_CPP
