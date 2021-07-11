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

#include <list>

#include "../util/built_in_functions.h"

namespace casbin {

class FunctionMap {
    public:
        Scope scope;
        std::list<std::string> func_list;

        FunctionMap();

        void ProcessFunctions(const std::string& expression);

        int GetRLen();

        bool Evaluate(const std::string& expression);

        bool GetBooleanResult();

        // AddFunction adds an expression function.
        void AddFunction(const std::string& func_name, Function f, Index nargs);

        void AddFunctionPropToR(const std::string& identifier, Function func, Index nargs);

        void AddBooleanPropToR(const std::string& identifier, bool val);

        void AddTruePropToR(const std::string& identifier);

        void AddFalsePropToR(const std::string& identifier);

        void AddIntPropToR(const std::string& identifier, int val);

        void AddFloatPropToR(const std::string& identifier, float val);

        void AddDoublePropToR(const std::string& identifier, double val);

        void AddStringPropToR(const std::string& identifier, const std::string& val);

        void AddPointerPropToR(const std::string& identifier, void* val);

        void AddObjectPropToR(const std::string& identifier);

        // LoadFunctionMap loads an initial function map.
        void LoadFunctionMap();

};

};  // namespace casbin

#endif