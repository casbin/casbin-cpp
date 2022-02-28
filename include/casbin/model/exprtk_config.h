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

#ifndef CASBIN_CPP_MODEL_EXPRTK_CONFIG
#define CASBIN_CPP_MODEL_EXPRTK_CONFIG

#include <memory>

#include "casbin/exprtk/exprtk.hpp"
#include "casbin/rbac/role_manager.h"
#include "casbin/rbac/default_role_manager.h"
#include "casbin/util/util.h"

namespace casbin {
    using numerical_type = float;

    using symbol_table_t = exprtk::symbol_table<numerical_type>;
    using expression_t = exprtk::expression<numerical_type>;
    using parser_t = exprtk::parser<numerical_type>;
    using exprtk_func_t = exprtk::igeneric_function<numerical_type>;

    struct ExprtkGFunction : public exprtk::igeneric_function<numerical_type>
    {
        typedef typename exprtk::igeneric_function<numerical_type>::generic_type
                                                        generic_type;

        typedef typename generic_type::scalar_view scalar_t;
        typedef typename generic_type::vector_view vector_t;
        typedef typename generic_type::string_view string_t;

        typedef typename exprtk::igeneric_function<numerical_type>::parameter_list_t
                                                        parameter_list_t;
    private:
        std::shared_ptr<casbin::RoleManager> rm_;
    public:
        ExprtkGFunction(const std::string& idenfier)
        : exprtk::igeneric_function<numerical_type>(idenfier), rm_(nullptr)
        {}

        ExprtkGFunction(const std::string& idenfier, std::shared_ptr<RoleManager> rm)
        : exprtk::igeneric_function<numerical_type>(idenfier), rm_(rm)
        {}

        bool UpdateRoleManager(std::shared_ptr<RoleManager> rm) {
            this->rm_ = rm;

            return true;
        }

        inline numerical_type operator()(parameter_list_t parameters) {        
            bool res = false;

            // check value cnt
            if (parameters.size() != 2 && parameters.size() != 3) {
                return numerical_type(res);
            }

            // check value type
            for (std::size_t i = 0; i < parameters.size(); ++i) {
                generic_type& gt = parameters[i];

                if (generic_type::e_scalar == gt.type) {
                    return numerical_type(res);
                }
                else if (generic_type::e_vector == gt.type) {
                    return numerical_type(res);
                }
            }

            std::string name1 = exprtk::to_str(string_t(parameters[0]));
            std::string name2 = exprtk::to_str(string_t(parameters[1]));
            std::string domain;
            std::vector<std::string> domains;

            if (parameters.size() == 3) {
                domain = exprtk::to_str(string_t(parameters[2]));
                domains.push_back(domain);
            }

            if(this->rm_ == nullptr)
                res = name1 == name2;
            else {
                res = rm_->HasLink(name1, name2, domains);
            }

            return numerical_type(res);
        }
    };


    struct ExprtkOtherFunction : public exprtk::igeneric_function<numerical_type>
    {
        typedef typename exprtk::igeneric_function<numerical_type>::generic_type
                                                        generic_type;

        typedef typename generic_type::scalar_view scalar_t;
        typedef typename generic_type::vector_view vector_t;
        typedef typename generic_type::string_view string_t;

        typedef typename exprtk::igeneric_function<numerical_type>::parameter_list_t
                                                        parameter_list_t;
    private:
        casbin::MatchingFunc func_;
    public:
        ExprtkOtherFunction(const std::string& idenfier, casbin::MatchingFunc func)
        : exprtk::igeneric_function<numerical_type>(idenfier), func_(func)
        {}

        ExprtkOtherFunction()
        : exprtk::igeneric_function<numerical_type>("ss")
        {}

        inline numerical_type operator()(parameter_list_t parameters) {        
            bool res = false;

            // check value cnt
            if (parameters.size() != 2) {
                return numerical_type(res);
            }

            // check value type
            for (std::size_t i = 0; i < parameters.size(); ++i) {
                generic_type& gt = parameters[i];

                if (generic_type::e_scalar == gt.type) {
                    return numerical_type(res);
                }
                else if (generic_type::e_vector == gt.type) {
                    return numerical_type(res);
                }
            }

            std::string name1 = exprtk::to_str(string_t(parameters[0]));
            std::string name2 = exprtk::to_str(string_t(parameters[1]));

            if(this->func_ == nullptr)
                res = name1 == name2;
            else {
                res = this->func_(name1, name2);
            }

            return numerical_type(res);
        }
    };

    enum class ExprtkFunctionType {
        Unknown,
        Gfunction,
        KeyMatch,
        KeyMatch2,
        KeyMatch3,
        RegexMatch,
        IpMatch,
    };

    class ExprtkFunctionFactory {
        public:
            static std::shared_ptr<exprtk_func_t> GetExprtkFunction(ExprtkFunctionType type, int narg, std::shared_ptr<RoleManager> rm = nullptr) {
                if (type == ExprtkFunctionType::Gfunction) {
                    std::string idenfier(narg, 'S');
                    return std::make_shared<ExprtkGFunction>(idenfier, rm);
                } else if (type != ExprtkFunctionType::Unknown) {
                    std::string idenfier(narg, 'S');
                    auto ret = std::make_shared<ExprtkOtherFunction>();
                    if (type == ExprtkFunctionType::KeyMatch) {
                        ret.reset(new ExprtkOtherFunction(idenfier, KeyMatch));
                        return ret;
                    } else if (type == ExprtkFunctionType::KeyMatch2) {
                        ret.reset(new ExprtkOtherFunction(idenfier, KeyMatch2));
                        return ret;
                    } else if (type == ExprtkFunctionType::KeyMatch3) {
                        ret.reset(new ExprtkOtherFunction(idenfier, KeyMatch3));
                        return ret;
                    } else if (type == ExprtkFunctionType::IpMatch) {
                        ret.reset(new ExprtkOtherFunction(idenfier, IPMatch));
                        return ret;
                    }
                } else {
                    return nullptr;
                }
            }
    };
}


#endif