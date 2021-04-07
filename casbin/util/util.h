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

#ifndef CASBIN_CPP_UTIL_UTIL
#define CASBIN_CPP_UTIL_UTIL

#include <vector>
#include <string>

namespace casbin {

// ArrayEquals determines whether two std::string arrays are identical.
bool ArrayEquals(std::vector<std::string> a, std::vector<std::string> b);

// ArrayRemoveDuplicates removes any duplicated elements in a std::string array.
void ArrayRemoveDuplicates(std::vector<std::string>& s);

std::string ArrayToString(std::vector<std::string> arr);

bool EndsWith(std::string base, std::string suffix);

/**
* escapeAssertion escapes the dots in the assertion, because the expression evaluation doesn't support such variable names.
*
* @param s the value of the matcher and effect assertions.
* @return the escaped value.
*/
std::string EscapeAssertion(std::string s);

std::vector<size_t> FindAllOccurences(std::string data, std::string toSearch);

template<typename Base, typename T>
bool IsInstanceOf(const T*);

std::vector<std::string> JoinSlice(std::string a, std::vector<std::string> slice);

std::string Join(std::vector<std::string> vos, std::string sep = " ");

// RemoveComments removes the comments starting with # in the text.
std::string RemoveComments(std::string s);

// SetSubtract returns the elements in `a` that aren't in `b`.
std::vector<std::string> SetSubtract(std::vector<std::string> a, std::vector<std::string> b);

std::vector<std::string> Split(std::string str, std::string del, int limit = 0);

std::string& LTrim(std::string& str, const std::string& chars = "\t\n\v\f\r ");
 
std::string& RTrim(std::string& str, const std::string& chars = "\t\n\v\f\r ");
 
std::string Trim(std::string& str, const std::string& chars = "\t\n\v\f\r ");

} // namespace casbin

#endif