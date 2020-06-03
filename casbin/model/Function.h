#ifndef CASBIN_CPP_MODEL_FUNCTION
#define CASBIN_CPP_MODEL_FUNCTION

#include <string>
#include <unordered_map>

#include "../util/built_in_functions.h"
#include "../duktape/scope.h"

using namespace std;

class FunctionMap {
    public:
        Scope scope;
        unordered_map <string, Function> func_map;

        FunctionMap(){
            scope = duk_create_heap_default();
        }

        int GetRLen(){
            bool found = FetchIdentifier(scope, "rlen");
            if(found)
                return GetInt(scope);
            return -1;
        }

        void Eval(string expression){
            duk_eval_string(scope, expression.c_str());
        }

        bool GetBooleanResult(){
            return bool(duk_get_boolean(scope, -1));
        }

        // AddFunction adds an expression function.
        void AddFunction(string func_name, Function f, Index nargs = VARARGS) {
            func_map[func_name] = f;
            PushFunction(this->scope, f, nargs, func_name);
        }

        void AddFunctionPropToR(string identifier, Function func, unsigned int nargs = VARARGS){
            PushFunctionPropToObject(scope, "r", func, nargs, identifier);
        }

        void AddBooleanPropToR(string identifier, bool val){
            PushBooleanPropToObject(scope, "r", val, identifier);
        }

        void AddTruePropToR(string identifier){
            PushTruePropToObject(scope, "r", identifier);
        }

        void AddFalsePropToR(string identifier){
            PushFalsePropToObject(scope, "r", identifier);
        }

        void AddIntPropToR(string identifier, int val){
            PushIntPropToObject(scope, "r", val, identifier);
        }

        void AddFloatPropToR(string identifier, float val){
            PushFloatPropToObject(scope, "r", val, identifier);
        }

        void AddDoublePropToR(string identifier, double val){
            PushDoublePropToObject(scope, "r", val, identifier);
        }

        void AddStringPropToR(string identifier, string val){
            PushStringPropToObject(scope, "r", val, identifier);
        }

        void AddPointerPropToR(string identifier, void* val){
            PushPointerPropToObject(scope, "r", val, identifier);
        }

        void AddObjectPropToR(string identifier){
            PushObjectPropToObject(scope, "r", identifier);
        }

        // LoadFunctionMap loads an initial function map.
        static FunctionMap LoadFunctionMap() {
            FunctionMap func_map;

            func_map.AddFunction("keyMatch", KeyMatch);
            func_map.AddFunction("keyMatch2", KeyMatch2);
            func_map.AddFunction("keyMatch3", KeyMatch3);
            func_map.AddFunction("regexMatch", RegexMatch);
            func_map.AddFunction("ipMatch", IPMatch);

            return func_map;
        }

};

#endif