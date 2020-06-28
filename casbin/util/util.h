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

using namespace std;

// ArrayEquals determines whether two string arrays are identical.
bool ArrayEquals(vector<string> a, vector<string> b);

// ArrayRemoveDuplicates removes any duplicated elements in a string array.
void ArrayRemoveDuplicates(vector<string> &s);

string ArrayToString(vector<string> arr);

bool EndsWith(string base, string suffix);

/**
* escapeAssertion escapes the dots in the assertion, because the expression evaluation doesn't support such variable names.
*
* @param s the value of the matcher and effect assertions.
* @return the escaped value.
*/
string EscapeAssertion(string s);

vector <size_t> FindAllOccurences(string data, string toSearch);

template<typename Base, typename T>
bool IsInstanceOf(const T*);

vector<string> JoinSlice(string a, vector<string> slice);

string Join(vector<string> vos, string sep = " ");

// RemoveComments removes the comments starting with # in the text.
string RemoveComments(string s);

// SetSubtract returns the elements in `a` that aren't in `b`.
vector<string> SetSubtract(vector<string> a, vector<string> b);

vector<string> Split(string str, string del, int limit = 0);

string& LTrim(string& str, const string& chars = "\t\n\v\f\r ");
 
string& RTrim(string& str, const string& chars = "\t\n\v\f\r ");
 
string Trim(string& str, const string& chars = "\t\n\v\f\r ");

#endif