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

namespace casbin {

    template <typename T>
    struct ExprtkGFunction : public exprtk::igeneric_function<T>
    {
        typedef typename exprtk::igeneric_function<T>::generic_type
                                                        generic_type;

        typedef typename generic_type::scalar_view scalar_t;
        typedef typename generic_type::vector_view vector_t;
        typedef typename generic_type::string_view string_t;

        typedef typename exprtk::igeneric_function<T>::parameter_list_t
                                                        parameter_list_t;
    private:
        std::shared_ptr<casbin::RoleManager> rm_;
    public:
        ExprtkGFunction()
        : exprtk::igeneric_function<T>("SS"), rm_(nullptr)
        {}

        ExprtkGFunction(std::shared_ptr<RoleManager> rm)
        : exprtk::igeneric_function<T>("SS"), rm_(rm)
        {}

        bool UpdateRoleManager(std::shared_ptr<RoleManager> rm) {
            this->rm_ = rm;

            return true;
        }

        inline T operator()(parameter_list_t parameters) {        
            bool res = false;

            // check value cnt
            if (parameters.size() < 2 || parameters.size() > 3) {
                return T(res);
            }

            // check value type
            for (std::size_t i = 0; i < parameters.size(); ++i) {
                generic_type& gt = parameters[i];

                if (generic_type::e_scalar == gt.type) {
                    return T(res);
                }
                else if (generic_type::e_vector == gt.type) {
                    return T(res);
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

            return T(res);
        }
    };
}


#endif