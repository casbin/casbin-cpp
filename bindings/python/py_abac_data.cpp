/*
* Copyright 2021 The casbin Authors. All Rights Reserved.
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

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <casbin/casbin.h>

namespace py = pybind11;

void bindABACData(py::module& m) {
    py::class_<casbin::ABACData>(m, "ABACData")
        .def(py::init<const casbin::AttributeMap &>(), R"doc(
            @brief Construct a new casbin::ABACData object

            @param attribs Should be of the format: {
            { "attrib_name1", value1 },
            { "attring_name2", value2 },
            ...
            }

            Key's type is std::string and value's type can be one of std::string, int32_t, double, and float only
        )doc")
        .def("AddAttribute", &casbin::ABACData::AddAttribute, R"doc(
            @brief Add attribute to the corresponding ABAC entity
            @param key Name of the attribute
            @param value Value of the attribute
            @return true when attribute is added successfully, false otherwise
        )doc")
        .def("AddAttributes", &casbin::ABACData::AddAttributes, R"doc(
            @brief Add attributes to the corresponding ABAC entity

            @param attribs Should be of the format: {
            { "attrib_name1", value1 },
            { "attring_name2", value2 },
            ...
            }

            Key's type is std::string and value's type can be one of std::string, int32_t, and float only
            @return true if attributes are added successfully, false otherwise

        )doc")
        .def("DeleteAttribute", &casbin::ABACData::DeleteAttribute, R"doc(
            @brief Delete attribute of the corresponding ABAC entity
            @param key Name of the attribute to be deleted
            @return true when attribute is deleted successfully, false otherwise
        )doc")
        .def("UpdateAttribute", &casbin::ABACData::UpdateAttribute, R"doc(
            @brief Update attribute of the corresponding ABAC entity
            @param key Name of the attribute to be updated
            @param value Value which would replace the current value of the attribute corresponding 
            to the given key
            @return true 
            @return false
        )doc");
        // .def("GetAttributes", &casbin::ABACData::GetAttributes, R"doc(
        //     @brief Get the Attributes of the corresponding ABAC entity
        //     @return const reference to the hashmap containing attributes in key-value pairs
        // )doc");

    m.def("GetDataObject", &casbin::GetDataObject, R"doc(
        @brief Get casbin::ABACData object
        @param attribs Should be of the format: {
        { "attrib_name1", value1 },
        { "attrib_name2", value2 },
        ...
        }
        Key's type is std::string and value's type can be one of std::string, int32_t, double, and float only
        @return Pointer to casbin::ABACData entity
    )doc");
}
