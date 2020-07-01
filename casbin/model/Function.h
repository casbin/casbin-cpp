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

        void ProcessFunctions(string expression);

        int GetRLen();

        bool Evaluate(string expression);

        bool GetBooleanResult();

        // AddFunction adds an expression function.
        void AddFunction(string func_name, Function f, Index nargs);

        void AddFunctionPropToR(string identifier, Function func, Index nargs);

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
        void LoadFunctionMap();

};

#endif