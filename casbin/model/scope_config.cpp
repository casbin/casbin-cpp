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

#ifndef SCOPE_CONFIG_CPP
#define SCOPE_CONFIG_CPP


#include "./scope_config.h"

namespace casbin {

Scope InitializeScope() {
    return duk_create_heap_default();
}

void DeinitializeScope(Scope scope) {
    duk_destroy_heap(scope);
}

void PushFunctionValue(Scope scope, Function f, int nargs) {
    duk_push_c_function(scope, f, (Index)nargs);
}

void PushBooleanValue(Scope scope, bool expression) {
    duk_push_boolean(scope, expression);
}

void PushTrueValue(Scope scope) {
    duk_push_true(scope);
}

void PushFalseValue(Scope scope) {
    duk_push_false(scope);
}

void PushIntValue(Scope scope, int integer) {
    duk_push_int(scope, integer);
}

void PushFloatValue(Scope scope, float f) {
    duk_push_number(scope, f);
}

void PushDoubleValue(Scope scope, double d) {
    duk_push_number(scope, d);
}

void PushStringValue(Scope scope, const std::string& s) {
    duk_push_string(scope, s.c_str());
}

void PushPointerValue(Scope scope, void * ptr) {
    duk_push_pointer(scope, ptr);
}

void PushObjectValue(Scope scope) {
    duk_push_global_object(scope);
}

void PushFunction(Scope scope, Function f, const std::string& fname, int nargs) {
    duk_push_c_function(scope, f, (Index)nargs);
    duk_put_global_string(scope, fname.c_str());
}

void PushBoolean(Scope scope, bool expression, const std::string& identifier) {
    duk_push_boolean(scope, expression);
    duk_put_global_string(scope, identifier.c_str());
}

void PushTrue(Scope scope, const std::string& identifier) {
    duk_push_true(scope);
    duk_put_global_string(scope, identifier.c_str());
}

void PushFalse(Scope scope, const std::string& identifier) {
    duk_push_false(scope);
    duk_put_global_string(scope, identifier.c_str());
}

void PushInt(Scope scope, int integer, const std::string& identifier) {
    duk_push_int(scope, integer);
    duk_put_global_string(scope, identifier.c_str());
}

void PushFloat(Scope scope, float f, const std::string& identifier) {
    duk_push_number(scope, f);
    duk_put_global_string(scope, identifier.c_str());
}

void PushDouble(Scope scope, double d, const std::string& identifier) {
    duk_push_number(scope, d);
    duk_put_global_string(scope, identifier.c_str());
}

void PushString(Scope scope, const std::string& s, const std::string& identifier) {
    duk_push_string(scope, s.c_str());
    duk_put_global_string(scope, identifier.c_str());
}

void PushPointer(Scope scope, void * ptr, const std::string& identifier) {
    duk_push_pointer(scope, ptr);
    duk_put_global_string(scope, identifier.c_str());
}

void PushObject(Scope scope, const std::string& identifier) {
    duk_push_object(scope);
    duk_put_global_string(scope, identifier.c_str());
    duk_push_int(scope, 0);
    duk_put_global_string(scope, (identifier+"len").c_str());
}

void PushFunctionPropToObject(Scope scope, const std::string& obj, Function f, const std::string& fname, int nargs) {
    duk_get_global_string(scope, obj.c_str());
    duk_push_c_function(scope, f, nargs);
    duk_put_prop_string(scope, -2, fname.c_str());
    duk_eval_string_noresult(scope, (obj+"len += 1;").c_str());
}

void PushBooleanPropToObject(Scope scope, const std::string& obj, bool expression, const std::string& identifier) {
    duk_get_global_string(scope, obj.c_str());
    duk_push_boolean(scope, expression);
    duk_put_prop_string(scope, -2, identifier.c_str());
    duk_eval_string_noresult(scope, (obj+"len += 1;").c_str());
}

void PushTruePropToObject(Scope scope, const std::string& obj, const std::string& identifier) {
    duk_get_global_string(scope, obj.c_str());
    duk_push_true(scope);
    duk_put_prop_string(scope, -2, identifier.c_str());
    duk_eval_string_noresult(scope, (obj+"len += 1;").c_str());
}

void PushFalsePropToObject(Scope scope, const std::string& obj, const std::string& identifier) {
    duk_get_global_string(scope, obj.c_str());
    duk_push_false(scope);
    duk_put_prop_string(scope, -2, identifier.c_str());
    duk_eval_string_noresult(scope, (obj+"len += 1;").c_str());
}

void PushIntPropToObject(Scope scope, const std::string& obj, int integer, const std::string& identifier) {
    duk_get_global_string(scope, obj.c_str());
    duk_push_int(scope, integer);
    duk_put_prop_string(scope, -2, identifier.c_str());
    duk_eval_string_noresult(scope, (obj+"len += 1;").c_str());
}

void PushFloatPropToObject(Scope scope, const std::string& obj, float f, const std::string& identifier) {
    duk_get_global_string(scope, obj.c_str());
    duk_push_number(scope, f);
    duk_put_prop_string(scope, -2, identifier.c_str());
    duk_eval_string_noresult(scope, (obj+"len += 1;").c_str());
}

void PushDoublePropToObject(Scope scope, const std::string& obj, double d, const std::string& identifier) {
    duk_get_global_string(scope, obj.c_str());
    duk_push_number(scope, d);
    duk_put_prop_string(scope, -2, identifier.c_str());
    duk_eval_string_noresult(scope, (obj+"len += 1;").c_str());
}

void PushStringPropToObject(Scope scope, const std::string& obj, const std::string& s, const std::string& identifier) {
    duk_get_global_string(scope, obj.c_str());
    duk_push_string(scope, s.c_str());
    duk_put_prop_string(scope, -2, identifier.c_str());
    duk_eval_string_noresult(scope, (obj+"len += 1;").c_str());
}

void PushPointerPropToObject(Scope scope, const std::string& obj, void * ptr, const std::string& identifier) {
    duk_get_global_string(scope, obj.c_str());
    duk_push_pointer(scope, ptr);
    duk_put_prop_string(scope, -2, identifier.c_str());
    duk_eval_string_noresult(scope, (obj+"len += 1;").c_str());
}

void PushObjectPropToObject(Scope scope, const std::string& obj, const std::string& identifier) {
    duk_get_global_string(scope, obj.c_str());
    duk_get_global_string(scope, identifier.c_str());
    duk_put_prop_string(scope, -2, identifier.c_str());
    duk_eval_string_noresult(scope, (obj+"len += 1;").c_str());
}

Type CheckType(Scope scope) {
    if(duk_is_boolean(scope, -1))
        return Type::Bool;
    else
        return Type::Float;
}

bool FetchIdentifier(Scope scope, const std::string& identifier) {
    return duk_get_global_string(scope, identifier.c_str());
}

unsigned int Size(Scope scope) {
    return (unsigned int)duk_get_top(scope);
}

bool GetBoolean(Scope scope, int id) {
    return bool(duk_to_boolean(scope, (Index)id));
}

int GetInt(Scope scope, int id) {
    return int(duk_to_number(scope, (Index)id));
}

float GetFloat(Scope scope, int id) {
    return float(duk_to_number(scope, (Index)id));
}

double GetDouble(Scope scope, int id) {
    return double(duk_to_number(scope, (Index)id));
}

std::string GetString(Scope scope, int id) {
    return std::string(duk_to_string(scope, (Index)id));
}

void* GetPointer(Scope scope, int id) {
    return (void *)duk_to_pointer(scope, (Index)id);
}

void Get(Scope scope, const std::string& identifier) {
    Eval(scope, identifier);
}

bool Eval(Scope scope, const std::string& expression) {
    PushStringValue(scope, expression);
    return duk_peval(scope)==0;
}

void EvalNoResult(Scope scope, const std::string& expression) {
    duk_eval_string_noresult(scope, expression.c_str());
}

} // namespace casbin

#endif // SCOPE_CONFIG_CPP
