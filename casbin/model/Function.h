#ifndef CASBIN_CPP_MODEL_FUNCTION
#define CASBIN_CPP_MODEL_FUNCTION

#include <unordered_map>
#include <string>

#include "../util/builtInFunctions.h"

using namespace std;
// package model

// import (
// 	"github.com/Knetic/govaluate"
// 	"github.com/casbin/casbin/v2/util"
// )

class FunctionMap {
    private:

        unordered_map<string, function>

    public:

        // AddFunction adds an expression function.
        void AddFunction(string name, function govaluate.ExpressionFunction) {
            fm[name] = function
        }

        // LoadFunctionMap loads an initial function map.
        FunctionMap LoadFunctionMap() {
            FunctionMap fm;

            fm.AddFunction("keyMatch", KeyMatchFunc);
            fm.AddFunction("keyMatch2", KeyMatch2Func);
            fm.AddFunction("keyMatch3", KeyMatch3Func);
            fm.AddFunction("keyMatch4", KeyMatch4Func);
            fm.AddFunction("regexMatch", RegexMatchFunc);
            fm.AddFunction("ipMatch", IPMatchFunc);

            return fm;
        }

};

// FunctionMap represents the collection of Function.
type FunctionMap map[string]govaluate.ExpressionFunction

#endif