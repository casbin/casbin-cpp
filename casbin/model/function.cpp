#pragma once

#include "pch.h"

#include "./function.h"

FunctionMap :: FunctionMap(){
    scope = duk_create_heap_default();
}

int FunctionMap :: GetRLen(){
    bool found = FetchIdentifier(scope, "rlen");
    if(found)
        return GetInt(scope);
    return -1;
}

void FunctionMap :: Eval(string expression){
    duk_eval_string(scope, expression.c_str());
}

bool FunctionMap :: GetBooleanResult(){
    return bool(duk_get_boolean(scope, -1));
}

// AddFunction adds an expression function.
void FunctionMap :: AddFunction(string func_name, Function f, Index nargs) {
    func_map[func_name] = f;
    PushFunction(this->scope, f, nargs, func_name);
}

void FunctionMap :: AddFunctionPropToR(string identifier, Function func, unsigned int nargs){
    PushFunctionPropToObject(scope, "r", func, nargs, identifier);
}

void FunctionMap :: AddBooleanPropToR(string identifier, bool val){
    PushBooleanPropToObject(scope, "r", val, identifier);
}

void FunctionMap :: AddTruePropToR(string identifier){
    PushTruePropToObject(scope, "r", identifier);
}

void FunctionMap :: AddFalsePropToR(string identifier){
    PushFalsePropToObject(scope, "r", identifier);
}

void FunctionMap :: AddIntPropToR(string identifier, int val){
    PushIntPropToObject(scope, "r", val, identifier);
}

void FunctionMap :: AddFloatPropToR(string identifier, float val){
    PushFloatPropToObject(scope, "r", val, identifier);
}

void FunctionMap :: AddDoublePropToR(string identifier, double val){
    PushDoublePropToObject(scope, "r", val, identifier);
}

void FunctionMap :: AddStringPropToR(string identifier, string val){
    PushStringPropToObject(scope, "r", val, identifier);
}

void FunctionMap :: AddPointerPropToR(string identifier, void* val){
    PushPointerPropToObject(scope, "r", val, identifier);
}

void FunctionMap :: AddObjectPropToR(string identifier){
    PushObjectPropToObject(scope, "r", identifier);
}

// LoadFunctionMap loads an initial function map.
FunctionMap FunctionMap :: LoadFunctionMap() {
    FunctionMap func_map;

    func_map.AddFunction("keyMatch", KeyMatch);
    func_map.AddFunction("keyMatch2", KeyMatch2);
    func_map.AddFunction("keyMatch3", KeyMatch3);
    func_map.AddFunction("regexMatch", RegexMatch);
    func_map.AddFunction("ipMatch", IPMatch);

    return func_map;
}