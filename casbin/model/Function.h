#ifndef CASBIN_CPP_MODEL_FUNCTION
#define CASBIN_CPP_MODEL_FUNCTION

#include <unordered_map>

#include "../util/built_in_functions.h"

using namespace std;

class FunctionMap {
    public:
        Scope scope;
        unordered_map <string, Function> func_map;

        FunctionMap();

        int GetRLen();

        void Eval(string expression);

        bool GetBooleanResult();

        // AddFunction adds an expression function.
        void AddFunction(string func_name, Function f, Index nargs = VARARGS);

        void AddFunctionPropToR(string identifier, Function func, unsigned int nargs = VARARGS);

        void AddBooleanPropToR(string identifier, bool val);

        void AddTruePropToR(string identifier);

        void AddFalsePropToR(string identifier);

        void AddIntPropToR(string identifier, int val);

        void AddFloatPropToR(string identifier, float val);

        void AddDoublePropToR(string identifier, double val);

        void AddStringPropToR(string identifier, string val);

        void AddPointerPropToR(string identifier, void* val);

        void AddObjectPropToR(string identifier);

        // LoadFunctionMap loads an initial function map.
        static FunctionMap LoadFunctionMap();

};

#endif