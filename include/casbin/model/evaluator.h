
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
#include "./model.h"
#include "./exprtk_config.h"

namespace casbin {

    enum class Type{
        Bool, Float
    };

    class IEvaluator {
        public:
            std::list<std::string> func_list;
            virtual bool Eval(const std::string& expression) = 0;

            virtual void InitialObject(const std::string& target) = 0;

            virtual void PushObjectString(const std::string& target, const std::string& proprity, const std::string& var) = 0;

            virtual void PushObjectJson(const std::string& target, const std::string& proprity, const nlohmann::json& var) = 0;

            virtual void LoadFunctions() = 0;

            virtual void LoadGFunction(std::shared_ptr<RoleManager> rm, const std::string& name, int narg) = 0;

            virtual void ProcessFunctions(const std::string& expression) = 0;

            virtual Type CheckType() = 0;

            virtual bool GetBoolen() = 0;

            virtual float GetFloat() = 0;

            virtual void Clean(AssertionMap& section, bool after_enforce = true) = 0;
    };

    class ExprtkEvaluator : public IEvaluator {
        private:
            std::string expression_string_;
            symbol_table_t symbol_table;
            expression_t expression;
            parser_t parser;
            std::vector<std::shared_ptr<exprtk_func_t>> Functions;
            std::unordered_map<std::string, std::unique_ptr<std::string>> identifiers_;
        public:
            ExprtkEvaluator() {
                this->expression.register_symbol_table(this->symbol_table);
            };
            bool Eval(const std::string& expression);

            void InitialObject(const std::string& target);

            void PushObjectString(const std::string& target, const std::string& proprity, const std::string& var);

            void PushObjectJson(const std::string& target, const std::string& proprity, const nlohmann::json& var);

            void LoadFunctions();

            void LoadGFunction(std::shared_ptr<RoleManager> rm, const std::string& name, int narg);

            void ProcessFunctions(const std::string& expression);

            Type CheckType();

            bool GetBoolen();

            float GetFloat();

            void Clean(AssertionMap& section, bool after_enforce = true);

            void PrintSymbol();

            void AddFunction(const std::string& func_name, std::shared_ptr<exprtk_func_t> func);

            void AddIdentifier(const std::string& identifier, const std::string& var);
    };
} // namespace casbin


#endif