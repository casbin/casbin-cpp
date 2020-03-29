#ifndef CASBIN_CPP_MODEL_DUKTAPE_CONFIG
#define CASBIN_CPP_MODEL_DUKTAPE_CONFIG

#include <string>

#include "../duktape/scope.h"

#define VARARGS DUK_VARARGS
#define RETURN_RESULT 1

enum TYPE{
    BOOL, FLOAT
};

typedef duk_context* Scope;
typedef duk_ret_t ReturnType;
typedef duk_c_function Function;
typedef duk_idx_t Index;

using namespace std;

void pushFunctionValue(Scope scope, Function f, int nargs){
    duk_push_c_function(scope, f, (Index)nargs);
}

void pushBooleanValue(Scope scope, bool expression){
    duk_push_boolean(scope, expression);
}

void pushTrueValue(Scope scope){
    duk_push_true(scope);
}

void pushFalseValue(Scope scope){
    duk_push_false(scope);
}

void pushIntValue(Scope scope, int integer){
    duk_push_int(scope, integer);
}

void pushFloatValue(Scope scope, float f){
    duk_push_number(scope, f);
}

void pushDoubleValue(Scope scope, double d){
    duk_push_number(scope, d);
}

void pushStringValue(Scope scope, string s){
    duk_push_string(scope, s.c_str());
}

void pushPointerValue(Scope scope, void * ptr){
    duk_push_pointer(scope, ptr);
}

void pushFunction(Scope scope, Function f, int nargs, string fname) {
    duk_push_c_function(scope, f, (Index)nargs);
    duk_put_global_string(scope, fname.c_str());
}

void pushBoolean(Scope scope, bool expression, string identifier){
    duk_push_boolean(scope, expression);
    duk_put_global_string(scope, identifier.c_str());
}

void pushTrueValue(Scope scope, string identifier){
    duk_push_true(scope);
    duk_put_global_string(scope, identifier.c_str());
}

void pushFalseValue(Scope scope, string identifier){
    duk_push_false(scope);
    duk_put_global_string(scope, identifier.c_str());
}

void pushIntValue(Scope scope, int integer, string identifier){
    duk_push_int(scope, integer);
    duk_put_global_string(scope, identifier.c_str());
}

void pushFloatValue(Scope scope, float f, string identifier){
    duk_push_number(scope, f);
    duk_put_global_string(scope, identifier.c_str());
}

void pushDoubleValue(Scope scope, double d, string identifier){
    duk_push_number(scope, d);
    duk_put_global_string(scope, identifier.c_str());
}

void pushStringValue(Scope scope, string s, string identifier){
    duk_push_string(scope, s.c_str());
    duk_put_global_string(scope, identifier.c_str());
}

void pushPointerValue(Scope scope, void * ptr, string identifier){
    duk_push_pointer(scope, ptr);
    duk_put_global_string(scope, identifier.c_str());
}

TYPE checkType(Scope scope){
    if(duk_is_boolean(scope, -1))
        return TYPE::BOOL;
    else if(duk_is_number(scope, -1))
        return TYPE::FLOAT;
}

void fetchIdentifier(Scope scope, string identifier){
    duk_get_global_string(scope, identifier.c_str());
}

unsigned int size(Scope scope){
    return (unsigned int)duk_get_top(scope);
}

string getString(Scope scope, int id = -1){
    return string(duk_to_string(scope, (Index)id));
}

int getInt(Scope scope, int id = -1){
    return int(duk_to_number(scope, (Index)id));
}

float getFloat(Scope scope, int id = -1){
    return float(duk_to_number(scope, (Index)id));
}

double getDouble(Scope scope, int id = -1){
    return double(duk_to_number(scope, (Index)id));
}

void* getPointer(Scope scope, int id = -1){
    return (void *)duk_to_pointer(scope, (Index)id);
}

#endif