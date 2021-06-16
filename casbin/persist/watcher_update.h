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

#ifndef WATCHER_UPDATE_H
#define WATCHER_UPDATE_H

#include "watcher.h"

namespace casbin {

/**
 * @brief WatcherUpdatable is the strengthen for Casbin watchers.
 * 
 */
class WatcherUpdatable : public Watcher {
public:
    /**
     * @brief UpdateForUpdatePolicy calls the update callback of other instances to synchronize their policy.
     * It is called after Enforcer::UpdatePolicy()
     * 
     * @param oldRule Old rule which is to be replaced
     * @param newRule New rule which will replace oldRule
     */
    virtual void UpdateForUpdatePolicy(const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule) = 0;
    /**
     * @brief UpdateForUpdatePolicies calls the update callback of other instances to synchronize their policy. 
     * It is called after Enforcer::UpdatePolicies()
     * 
     * @param oldRules Old rules which are to be replaced
     * @param newRules New rules which will replace oldRules
     */
    virtual void UpdateForUpdatePolicies(const std::vector<std::vector<std::string>>& oldRules, const std::vector<std::vector<std::string>>& newRules) = 0;
};

}

#endif
