#ifndef CASBIN_CPP_MODEL_FUNCTION
#define CASBIN_CPP_MODEL_FUNCTION

#include <string>

#include "../util/builtInFunctions.h"
#include "../duktape/scope.h"

using namespace std;

class FunctionMap {
        unsigned int rlen;
    public:
        Scope scope;
        unordered_map<string, Function> fmap;

        FunctionMap(){
            scope = duk_create_heap_default();
            rlen = 0;
        }

        unsigned int getRLen(){
            return rlen;
        }

        void Eval(string expression){
            duk_eval_string(scope, expression.c_str());
        }

        bool getBooleanResult(){
            return bool(duk_get_boolean(scope, -1));
        }

        // AddFunction adds an expression function.
        void AddFunction(string fname, Function f, Index nargs = VARARGS) {
            fmap[fname] = f;
            pushFunction(this->scope, f, nargs, fname);
        }

        void AddFunctionPropToR(string identifier, Function f, unsigned int nargs = VARARGS){
            pushFunctionPropToObject(scope, "r", f, nargs, identifier);
            rlen++;
        }

        void AddBooleanPropToR(string identifier, bool val){
            pushBooleanPropToObject(scope, "r", val, identifier);
            rlen++;
        }

        void AddTruePropToR(string identifier){
            pushTruePropToObject(scope, "r", identifier);
            rlen++;
        }

        void AddFalsePropToR(string identifier){
            pushFalsePropToObject(scope, "r", identifier);
            rlen++;
        }

        void AddIntPropToR(string identifier, int val){
            pushIntPropToObject(scope, "r", val, identifier);
            rlen++;
        }

        void AddFloatPropToR(string identifier, float val){
            pushFloatPropToObject(scope, "r", val, identifier);
            rlen++;
        }

        void AddDoublePropToR(string identifier, double val){
            pushDoublePropToObject(scope, "r", val, identifier);
            rlen++;
        }

        void AddStringPropToR(string identifier, string val){
            pushStringPropToObject(scope, "r", val, identifier);
            rlen++;
        }

        void AddPointerPropToR(string identifier, void* val){
            pushPointerPropToObject(scope, "r", val, identifier);
            rlen++;
        }

        void AddObjectPropToR(string identifier){
            pushObjectPropToObject(scope, "r", identifier);
            rlen++;
        }

        // LoadFunctionMap loads an initial function map.
        static FunctionMap LoadFunctionMap() {
            FunctionMap fm;

            fm.AddFunction("keyMatch", KeyMatch);
            fm.AddFunction("keyMatch2", KeyMatch2);
            fm.AddFunction("keyMatch3", KeyMatch3);
            fm.AddFunction("regexMatch", RegexMatch);
            fm.AddFunction("ipMatch", IPMatch);

            return fm;
        }

};

#endif