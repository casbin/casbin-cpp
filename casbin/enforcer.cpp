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

#include "pch.h"
#include "enforcer.h"

bool Enforcer::enforce(string sub, string obj, string act) {
	/*string request = sub + "," + obj + "," + act;
	vector<string> policyeffects;
	for (vector<string> ele : pmanager.getFilteredPolicy("p")) {
		string response = m.injectValue(mmanager.getRPStructure(), request, join(ele, ','), m.matcherString);
		response = m.parseString(response);
		policyeffects.push_back(response);
	}

	return m.mergeDecisions(policyeffects);*/
	return true;
}

vector<string> Enforcer::getPolicy() {
	vector<vector<string>> temp = pmanager.getPolicy();
	vector<string> result;
	for (vector<string> ele : temp) {
		result.push_back(join(ele, ','));
	}

	return result;
}
