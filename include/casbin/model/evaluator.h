
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

#ifndef CASBIN_CPP_MODEL_EVALATOR_CONFIG
#define CASBIN_CPP_MODEL_EVALATOR_CONFIG

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

#include "../exprtk/exprtk.hpp"
#include "./scope_config.h"
#include "./model.h"

namespace casbin {

    using numerical_type = float;

    using symbol_table_t = exprtk::symbol_table<numerical_type>;
    using expression_t = exprtk::expression<numerical_type>;
    using parser_t = exprtk::parser<numerical_type>;
    using exprtk_func_t = exprtk::igeneric_function<numerical_type>;

    class IEvaluator {
        public:
            std::list<std::string> func_list;
            virtual bool Eval(const std::string& expression) = 0;

            virtual void InitialObject(std::string target) = 0;

            virtual void PushObjectString(std::string target, std::string proprity, const std::string& var) = 0;

            virtual void PushObjectJson(std::string target, std::string proprity, const nlohmann::json& var) = 0;

            virtual void LoadFunctions() = 0;

            virtual void LoadGFunction(std::shared_ptr<RoleManager> rm, const std::string& name, int narg) = 0;

            virtual void ProcessFunctions(const std::string& expression) = 0;

            virtual Type CheckType() = 0;

            virtual bool GetBoolen() = 0;

            virtual float GetFloat() = 0;

            virtual void Clean(AssertionMap& section) = 0;
    };

    class ExprtkEvaluator : public IEvaluator {
        private:
            symbol_table_t symbol_table;
            expression_t expression;
            parser_t parser;
            std::vector<std::shared_ptr<exprtk_func_t>> Functions;
        public:
            bool Eval(const std::string& expression);

            void InitialObject(std::string target);

            void PushObjectString(std::string target, std::string proprity, const std::string& var);

            void PushObjectJson(std::string target, std::string proprity, const nlohmann::json& var);

            void LoadFunctions();

            void LoadGFunction(std::shared_ptr<RoleManager> rm, const std::string& name, int narg);

            void ProcessFunctions(const std::string& expression);

            Type CheckType();

            bool GetBoolen();

            float GetFloat();

            void Clean(AssertionMap& section);

            void PrintSymbol();

            void AddFunction(const std::string& func_name, std::shared_ptr<exprtk_func_t> func);
    };

    class DuktapeEvaluator : public IEvaluator {
        private:
            Scope scope;
        public:
            DuktapeEvaluator(Scope scope_) : scope(scope_) {};

            DuktapeEvaluator() : scope(InitializeScope()) {};

            ~DuktapeEvaluator() {
                DeinitializeScope(scope);
            };

            bool Eval(const std::string& expression);

            void InitialObject(std::string target);
            
            void PushObjectString(std::string target, std::string proprity, const  std::string& var);
            
            void PushObjectJson(std::string target, std::string proprity, const nlohmann::json& var);

            void LoadFunctions();

            void LoadGFunction(std::shared_ptr<RoleManager> rm, const std::string& name, int narg);
            
            void ProcessFunctions(const std::string& expression);

            Type CheckType();

            bool GetBoolen();

            float GetFloat();

            void Clean(AssertionMap& section);
            // For duktape
            void AddFunction(const std::string& func_name, Function f, Index nargs);

            int GetRLen();

            bool GetBooleanResult();

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

    };
} // namespace casbin


#endif