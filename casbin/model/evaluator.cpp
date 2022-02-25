/*
* Copyright 2022 The casbin Authors. All Rights Reserved.
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
#include <regex>

#include "casbin/model/evaluator.h"
#include "casbin/model/exprtk_config.h"
#include "casbin/util/util.h"

namespace casbin {
    bool ExprtkEvaluator::Eval(const std::string& expression_string) {
        expression.register_symbol_table(symbol_table);
        // replace (&& -> and), (|| -> or)
        auto replaced_string = std::regex_replace(expression_string, std::regex("&&"), "and");
        replaced_string = std::regex_replace(replaced_string, std::regex("\\|{2}"), "or");
        // replace string "" -> ''
        replaced_string = std::regex_replace(replaced_string, std::regex("\""), "\'");

        return parser.compile(replaced_string, expression);
    }

    void ExprtkEvaluator::InitialObject(std::string identifier) {
        // symbol_table.add_stringvar("");
    }

    void ExprtkEvaluator::PushObjectString(std::string target, std::string proprity, const std::string& var) {
        auto identifier = target + "." + proprity;
        this->symbol_table.add_stringvar(identifier, const_cast<std::string&>(var));
    }

    void ExprtkEvaluator::PushObjectJson(std::string target, std::string proprity, const nlohmann::json& var) {
        auto identifier = target + "." + proprity;
        // this->symbol_table.add_stringvar(identifier, const_cast<std::string&>(var));
    }

    void ExprtkEvaluator::LoadFunctions() {
        
    }

    void ExprtkEvaluator::LoadGFunction(std::shared_ptr<RoleManager> rm, const std::string& name, int narg) {
        std::shared_ptr<exprtk_func_t> func = std::make_shared<ExprtkGFunction<numerical_type>>(rm);
        this->AddFunction(name, func);
    }

    void ExprtkEvaluator::ProcessFunctions(const std::string& expression) {

    }

    Type ExprtkEvaluator::CheckType() {
        if (expression.value() == float(0) || expression.value() == float(1)) {
            return Type::Bool;
        } else {
            return Type::Float;
        }
    }

    bool ExprtkEvaluator::GetBoolen() {
        return expression.value();
    }

    float ExprtkEvaluator::GetFloat() {
        return expression.value();
    }

    void ExprtkEvaluator::Clean(AssertionMap& section) {
        for (auto& [assertion_name, assertion]: section.assertion_map) {
            std::vector<std::string> raw_tokens = assertion->tokens;

            for(int j = 0 ; j < raw_tokens.size() ; j++) {
                size_t index = raw_tokens[j].find("_");
                std::string token = raw_tokens[j].substr(index + 1);
                auto identifier = assertion_name + "." + token;
                if (symbol_table.get_stringvar(identifier) != nullptr) {
                    symbol_table.remove_stringvar(identifier);
                }
            }
        }
    }

    void ExprtkEvaluator::AddFunction(const std::string& func_name, std::shared_ptr<exprtk_func_t> func) {
        this->Functions.push_back(func);
        symbol_table.add_function(func_name, *func);
    }

    void ExprtkEvaluator::PrintSymbol() {
        std::vector<std::string> var_list;
        symbol_table.get_stringvar_list(var_list);

        printf("Current symboltable: \n");
        for (auto& var: var_list) {
            printf(" %s: %s\n" , var.c_str(), symbol_table.get_stringvar(var)->ref().c_str());
        }
    }

    bool DuktapeEvaluator::Eval(const std::string& expression) {
        return casbin::Eval(scope, expression);
    }

    void DuktapeEvaluator::InitialObject(std::string identifier) {
        PushObject(scope, identifier);
    }

    void DuktapeEvaluator::PushObjectString(std::string target, std::string proprity, const std::string& var) {
        PushStringPropToObject(scope, target, var, proprity);
    }

    void DuktapeEvaluator::PushObjectJson(std::string target, std::string proprity, const nlohmann::json& var) {
        PushObject(scope, proprity);
        PushObjectPropFromJson(scope, var, proprity);
        PushObjectPropToObject(scope, target, proprity);
    }

    void DuktapeEvaluator::LoadFunctions() {
        AddFunction("keyMatch", KeyMatch, 2);
        AddFunction("keyMatch2", KeyMatch2, 2);
        AddFunction("keyMatch3", KeyMatch3, 2);
        AddFunction("regexMatch", RegexMatch, 2);
        AddFunction("ipMatch", IPMatch, 2);
    }

    void DuktapeEvaluator::LoadGFunction(std::shared_ptr<RoleManager> rm, const std::string& name, int narg) {
        PushPointer(scope, reinterpret_cast<void *>(rm.get()), "rm");
        AddFunction(name, GFunction, narg);
    }

    void DuktapeEvaluator::AddFunction(const std::string& func_name, Function f, Index nargs) {
        func_list.push_back(func_name);
        PushFunction(scope, f, func_name, nargs);
    }

    void DuktapeEvaluator::ProcessFunctions(const std::string& expression) {
        for(const std::string& func: func_list) {
            size_t index = expression.find(func+"(");

            if (index != std::string::npos) {
                size_t close_index = expression.find(")", index);
                size_t start = index + func.length() + 1;

                std::string function_params = expression.substr(start, close_index - start);
                FetchIdentifier(this->scope, func);
                std::vector<std::string> params = Split(function_params, ",");

                for(std::string& param : params) {
                    size_t quote_index = param.find("\"");

                    if (quote_index == std::string::npos)
                        Get(this->scope, Trim(param));

                    else {
                        param = param.replace(quote_index, 1, "'");
                        size_t second_quote_index = param.find("\"", quote_index + 1);
                        param = param.replace(second_quote_index, 1, "'");
                        Get(this->scope, Trim(param));
                    }
                }
            }
        }
    }

    Type DuktapeEvaluator::CheckType() {
        return casbin::CheckType(scope);
    }

    bool DuktapeEvaluator::GetBoolen() {
        return casbin::GetBoolean(scope);
    }

    float DuktapeEvaluator::GetFloat() {
        return casbin::GetFloat(scope);
    }

    void DuktapeEvaluator::Clean(AssertionMap& section) {
        if (scope != nullptr) {
            for (auto& [assertion_name, assertion]: section.assertion_map) {
                std::vector<std::string> raw_tokens = assertion->tokens;

                for(int j = 0 ; j < raw_tokens.size() ; j++) {
                    size_t index = raw_tokens[j].find("_");
                    std::string token = raw_tokens[j].substr(index + 1);
                    DeletePropFromObject(scope, assertion_name, token);
                }
            }
        }
    }

    int DuktapeEvaluator::GetRLen(){
        bool found = FetchIdentifier(scope, "rlen");
        if(found)
            return GetInt(scope);
        return -1;
    }

    bool DuktapeEvaluator::GetBooleanResult() {
        return static_cast<bool>(duk_get_boolean(scope, -1));
    }

    void DuktapeEvaluator::AddFunctionPropToR(const std::string& identifier, Function func, Index nargs){
        PushFunctionPropToObject(scope, "r", func, identifier, nargs);
    }

    void DuktapeEvaluator::AddBooleanPropToR(const std::string& identifier, bool val){
        PushBooleanPropToObject(scope, "r", val, identifier);
    }

    void DuktapeEvaluator::AddTruePropToR(const std::string& identifier){
        PushTruePropToObject(scope, "r", identifier);
    }

    void DuktapeEvaluator::AddFalsePropToR(const std::string& identifier){
        PushFalsePropToObject(scope, "r", identifier);
    }

    void DuktapeEvaluator::AddIntPropToR(const std::string& identifier, int val){
        PushIntPropToObject(scope, "r", val, identifier);
    }

    void DuktapeEvaluator::AddFloatPropToR(const std::string& identifier, float val){
        PushFloatPropToObject(scope, "r", val, identifier);
    }

    void DuktapeEvaluator::AddDoublePropToR(const std::string& identifier, double val){
        PushDoublePropToObject(scope, "r", val, identifier);
    }

    void DuktapeEvaluator::AddStringPropToR(const std::string& identifier, const std::string& val){
        PushStringPropToObject(scope, "r", val, identifier);
    }

    void DuktapeEvaluator::AddPointerPropToR(const std::string& identifier, void* val){
        PushPointerPropToObject(scope, "r", val, identifier);
    }

    void DuktapeEvaluator::AddObjectPropToR(const std::string& identifier){
        PushObjectPropToObject(scope, "r", identifier);
    }
} // namespace casbin