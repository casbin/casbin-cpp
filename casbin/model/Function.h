#ifndef CASBIN_CPP_MODEL_FUNCTION
#define CASBIN_CPP_MODEL_FUNCTION

#include <string>

#include "../util/builtInFunctions.h"
#include "../duktape/duk_config.h"
#include "./duktape_config.h"

using namespace std;

class FunctionMap {
    private:
        Scope scope;

    public:

        FunctionMap(){
            scope = duk_create_heap_default();
        }

        // AddFunction adds an expression function.
        void AddFunction(string fname, Function f, Index nargs = VARARGS) {
            pushFunction(this->scope, f, nargs, fname);
        }

        // LoadFunctionMap loads an initial function map.
        FunctionMap LoadFunctionMap() {
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