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

#ifndef CASBIN_CPP_MODEL_SCOPE_CONFIG
#define CASBIN_CPP_MODEL_SCOPE_CONFIG

#include "pch.h"

#include <string>

#include "../duktape/duktape.h"
#include "../duktape/duk_config.h"

#define VARARGS DUK_VARARGS
#define RETURN_RESULT 1

namespace casbin {

enum Type{
    Bool, Float
};

typedef duk_context* Scope;
typedef duk_context PScope;
typedef duk_ret_t ReturnType;
typedef duk_c_function Function;
typedef duk_idx_t Index;

Scope InitializeScope();
void DeinitializeScope(Scope scope);
void PushFunctionValue(Scope scope, Function f, int nargs);
void PushBooleanValue(Scope scope, bool expression);
void PushTrueValue(Scope scope);
void PushFalseValue(Scope scope);
void PushIntValue(Scope scope, int integer);
void PushFloatValue(Scope scope, float f);
void PushDoubleValue(Scope scope, double d);
void PushStringValue(Scope scope, const std::string& s);
void PushPointerValue(Scope scope, void * ptr);
void PushObjectValue(Scope scope);
void PushFunction(Scope scope, Function f, const std::string& fname, int nargs);
void PushBoolean(Scope scope, bool expression, const std::string& identifier);
void PushTrue(Scope scope, const std::string& identifier);
void PushFalse(Scope scope, const std::string& identifier);
void PushInt(Scope scope, int integer, const std::string& identifier);
void PushFloat(Scope scope, float f, const std::string& identifier);
void PushDouble(Scope scope, double d, const std::string& identifier);
void PushString(Scope scope, const std::string& s, const std::string& identifier);
void PushPointer(Scope scope, void * ptr, const std::string& identifier);
void PushObject(Scope scope, const std::string& identifier = "r");
void PushFunctionPropToObject(Scope scope, const std::string& obj, Function f, const std::string& fname, int nargs);
void PushBooleanPropToObject(Scope scope, const std::string& obj, bool expression, const std::string& identifier);
void PushTruePropToObject(Scope scope, const std::string& obj, const std::string& identifier);
void PushFalsePropToObject(Scope scope, const std::string& obj, const std::string& identifier);
void PushIntPropToObject(Scope scope, const std::string& obj, int integer, const std::string& identifier);
void PushFloatPropToObject(Scope scope, const std::string& obj, float f, const std::string& identifier);
void PushDoublePropToObject(Scope scope, const std::string& obj, double d, const std::string& identifier);
void PushStringPropToObject(Scope scope, const std::string& obj, const std::string& s, const std::string& identifier);
void PushPointerPropToObject(Scope scope, const std::string& obj, void * ptr, const std::string& identifier);
void PushObjectPropToObject(Scope scope, const std::string& obj, const std::string& identifier);
Type CheckType(Scope scope);
bool FetchIdentifier(Scope scope, const std::string& identifier);
unsigned int Size(Scope scope);
bool GetBoolean(Scope scope, int id = -1);
int GetInt(Scope scope, int id = -1);
float GetFloat(Scope scope, int id = -1);
double GetDouble(Scope scope, int id = -1);
std::string GetString(Scope scope, int id = -1);
void* GetPointer(Scope scope, int id = -1);
void Get(Scope scope, const std::string& identifier);
bool Eval(Scope scope, const std::string& expression);
void EvalNoResult(Scope scope, const std::string& expression);

} // namespace casbin

#endif