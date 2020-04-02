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
#ifndef CASBIN_CPP_ENFORCER
#define CASBIN_CPP_ENFORCER

#include "./exception/CasbinEnforcerException.h"
#include "./model/Model.h"
#include "./model/Function.h"
#include "./rbac/DefaultRoleManager.h"
#include "./effect/DefaultEffector.h"
#include "./enforcer_interface.h"
#include "./persist/file-adapter/File_Adapter.h"
#include "./persist/file-adapter/Filtered_Adapter.h"

// Enforcer is the main interface for authorization enforcement and policy management.
class Enforcer : public IEnforcer{
	private:

		string modelPath;
		Model model;
		FunctionMap fm;
		Effector* eft;

		Adapter* adapter;
		Watcher* watcher;
		RoleManager* rm;

		bool enabled;
		bool autoSave;
		bool autoBuildRoleLinks;
		bool autoNotifyWatcher;

	public:

		/**
		 * Enforcer is the default constructor.
		 */
		static Enforcer NewEnforcer() {
			Enforcer e;
			return e;
		}

		/**
		 * Enforcer initializes an enforcer with a model file and a policy file.
		 *
		 * @param modelPath the path of the model file.
		 * @param policyFile the path of the policy file.
		 */
		static Enforcer NewEnforcer(string modelPath, string policyFile) {
			return NewEnforcer(modelPath, FileAdapter :: NewAdapter(policyFile));
		}

		/**
		 * Enforcer initializes an enforcer with a database adapter.
		 *
		 * @param modelPath the path of the model file.
		 * @param adapter the adapter.
		 */
		static Enforcer NewEnforcer(string modelPath, Adapter* adapter) {
			Enforcer e;
			e = NewEnforcer(Model :: NewModelFromFile(modelPath), adapter);
			e.modelPath = modelPath;
			return e;
		}

		/**
		 * Enforcer initializes an enforcer with a model and a database adapter.
		 *
		 * @param m the model.
		 * @param adapter the adapter.
		 */
		static Enforcer NewEnforcer(Model m, Adapter* adapter) {
			Enforcer e;
			e.adapter = adapter;
			e.watcher = NULL;

			e.model = m;
			e.model.PrintModel();
			e.fm.LoadFunctionMap();

			e.initialize();

			if (e.adapter != NULL) {
				e.LoadPolicy();
			}
			return e;
		}

		/**
		 * Enforcer initializes an enforcer with a model.
		 *
		 * @param m the model.
		 */
		static Enforcer NewEnforcer(Model m) {
			return NewEnforcer(m, NULL);
		}

		/**
		 * Enforcer initializes an enforcer with a model file.
		 *
		 * @param modelPath the path of the model file.
		 */
		static Enforcer NewEnforcer(string modelPath) {
			return NewEnforcer(modelPath, "");
		}

		/**
		 * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
		 *
		 * @param modelPath the path of the model file.
		 * @param policyFile the path of the policy file.
		 * @param enableLog whether to enable Casbin's log.
		 */
		static Enforcer NewEnforcer(string modelPath, string policyFile, bool enableLog) {
			Enforcer e;
			e = NewEnforcer(modelPath, FileAdapter :: NewAdapter(policyFile));
			e.EnableLog(enableLog);
			return e;
		}

		void func(string str) {
			this->LoadPolicy();
		}

		// InitWithFile initializes an enforcer with a model file and a policy file.
		void InitWithFile(string modelPath, string policyPath) {
			Adapter* a = FileAdapter::NewAdapter(policyPath);
			this->InitWithAdapter(modelPath, a);
		}

		// InitWithAdapter initializes an enforcer with a database adapter.
		void InitWithAdapter(string modelPath, Adapter* adapter) {
			Model m = Model :: NewModelFromFile(modelPath);

			this->InitWithModelAndAdapter(m, adapter);

			this->modelPath = modelPath;
		}

		// InitWithModelAndAdapter initializes an enforcer with a model and a database adapter.
		void InitWithModelAndAdapter(Model m, Adapter* adapter) {
			this->adapter = adapter;

			this->model = m;
			this->model.PrintModel();
			this->fm.LoadFunctionMap();

			this->initialize();

			// Do not initialize the full policy when using a filtered adapter
			if(this->adapter != NULL && !this->adapter->IsFiltered()) 
				this->LoadPolicy();
		}

		void initialize() {
			this->rm = DefaultRoleManager :: NewRoleManager(10);
			this->eft = DefaultEffector :: NewDefaultEffector();
			this->watcher = NULL;

			this->enabled = true;
			this->autoSave = true;
			this->autoBuildRoleLinks = true;
			this->autoNotifyWatcher = true;
		}

		// LoadModel reloads the model from the model CONF file.
		// Because the policy is attached to a model, so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
		void LoadModel() {
			this->model = Model :: NewModelFromFile(this->modelPath);

			this->model.PrintModel();
			this->fm.LoadFunctionMap();

			this->initialize();
		}

		// GetModel gets the current model.
		Model GetModel() {
			return this->model;
		}

		// SetModel sets the current model.
		void SetModel(Model m) {
			this->model = m;
			this->fm.LoadFunctionMap();

			this->initialize();
		}

		// GetAdapter gets the current adapter.
		Adapter* GetAdapter() {
			return this->adapter;
		}

		// SetAdapter sets the current adapter.
		void SetAdapter(Adapter* adapter) {
			this->adapter = adapter;
		}

		// SetWatcher sets the current watcher.
		void SetWatcher(Watcher* watcher) {
			this->watcher = watcher;
			watcher->SetUpdateCallback(func);
		}

		// GetRoleManager gets the current role manager.
		RoleManager* GetRoleManager() {
			return this->rm;
		}

		// SetRoleManager sets the current role manager.
		void SetRoleManager(RoleManager* rm) {
			this->rm = rm;
		}

		// SetEffector sets the current effector.
		void SetEffector(Effector* eft) {
			this->eft = eft;
		}

		// ClearPolicy clears all policy.
		void ClearPolicy() {
			this->model.ClearPolicy();
		}

		// LoadPolicy reloads the policy from file/database.
		void LoadPolicy() {
			this->model.ClearPolicy();
			this->adapter->LoadPolicy(this->model);

			this->model.PrintPolicy();

			if(this->autoBuildRoleLinks) {
				this->BuildRoleLinks();
			}
		}

		//LoadFilteredPolicy reloads a filtered policy from file/database.
        void LoadFilteredPolicy(Filter* filter) {
			this->model.ClearPolicy();

			FilteredAdapter* filteredAdapter;

			if(this->adapter->IsFiltered)
				filteredAdapter = (FilteredAdapter*)this->adapter;
			else
				throw CasbinAdapterException("filtered policies are not supported by this adapter");

			filteredAdapter->LoadFilteredPolicy(this->model, filter);

			this->model.PrintPolicy();
			if(this->autoBuildRoleLinks)
				this->BuildRoleLinks();
		}

		// IsFiltered returns true if the loaded policy has been filtered.
		bool IsFiltered() {
			return this->adapter->IsFiltered();
		}

		// SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
		void SavePolicy() {
			if(this->IsFiltered())
				throw CasbinEnforcerException("cannot save a filtered policy");

			this->adapter->SavePolicy(this->model);

			if(this->watcher != NULL)
				return this->watcher->Update();
		}

		// EnableEnforce changes the enforcing state of Casbin, when Casbin is disabled, all access will be allowed by the Enforce() function.
		void EnableEnforce(bool enable) {
			this->enabled = enable;
		}

		// EnableLog changes whether Casbin will log messages to the Logger.
		void EnableLog(bool enable) {
			// log.GetLogger().EnableLog(enable);
		}

		// EnableAutoNotifyWatcher controls whether to save a policy rule automatically notify the Watcher when it is added or removed.
		void EnableAutoNotifyWatcher(bool enable) {
			this->autoNotifyWatcher = enable;
		}

		// EnableAutoSave controls whether to save a policy rule automatically to the adapter when it is added or removed.
		void EnableAutoSave(bool autoSave) {
			this->autoSave = autoSave;
		}

		// EnableAutoBuildRoleLinks controls whether to rebuild the role inheritance relations when a role is added or deleted.
		void EnableAutoBuildRoleLinks(bool autoBuildRoleLinks) {
			this->autoBuildRoleLinks = autoBuildRoleLinks;
		}

		// BuildRoleLinks manually rebuild the role inheritance relations.
		void BuildRoleLinks() {
			this->rm->Clear();

			this->model.BuildRoleLinks(this->rm);
		}

		// enforce use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
		bool enforce(string matcher) {
			// TODO
			// defer func() {
			// 	if err := recover(); err != nil {
			// 		fmt.Errorf("panic: %v", err)
			// 	}
			// }()

			if(this->enabled)
				return true;

			for(unordered_map <string, Function> :: iterator it = this->fm.fmap.begin() ; it != this->fm.fmap.end() ; it++)
				this->fm.AddFunction(it->first, it->second);

			string expString;
			if(matcher == "")
				expString = this->model.M["m"].AMap["m"]->Value;
			else
				expString = matcher;

			unordered_map <string, RoleManager*> rm_map;
			bool ok = this->model.M.find("g") != this->model.M.end();
			if(ok) {
				for(unordered_map <string, Assertion*> :: iterator it = this->model.M["g"].AMap.begin() ; it != this->model.M["g"].AMap.end() ; it++){
					RoleManager* rm = it->second->RM;
					int index = expString.find((it->first)+"(");
					if(index != string::npos)
						expString.insert(index+(it->first+"(").length()-1, (it->first)+"_rm");
					pushPointer(this->fm.scope, (void *)rm, (it->first)+"_rm");
					this->fm.AddFunction(it->first, GFunction);
				}
			}

			unordered_map <string, int> pIntTokens;
			for(int i = 0 ; i < this->model.M["p"].AMap["p"]->Tokens.size() ; i++)
				pIntTokens[this->model.M["p"].AMap["p"]->Tokens[i]] = i;

			vector <string> pTokens = this->model.M["p"].AMap["p"]->Tokens;

			vector <Effect> policyEffects;
			vector <float> matcherResults;

			int policyLen = this->model.M["p"].AMap["p"]->Policy.size();

			if(policyLen != 0) {
				if(this->model.M["r"].AMap["r"]->Tokens.size() != this->fm.getRLen())
					return false;

				//TODO
				for( int i = 0 ; i < this->model.M["p"].AMap["p"]->Policy.size() ; i++){
					// log.LogPrint("Policy Rule: ", pvals)
					vector<string> pVals = this->model.M["p"].AMap["p"]->Policy[i];
					if(this->model.M["p"].AMap["p"]->Tokens.size() != pVals.size())
						return false;

					pushObject(this->fm.scope, "p");
					for(int j = 0 ; j < pTokens.size() ; j++){
						int index = pTokens[j].find("_");
						string token = pTokens[j].substr(index+1);
						pushStringPropToObject(this->fm.scope, "p", pVals[j], token);
					}

					this->fm.Eval(expString);
					//TODO
					// log.LogPrint("Result: ", result)

					if(checkType(this->fm.scope) == Type :: Bool){
						bool result = getBoolean(this->fm.scope);
						if(!result) {
							policyEffects[i] = Effect :: Indeterminate;
							continue;
						}
					}
					else if(checkType(this->fm.scope) == Type :: Float){
						bool result = getFloat(this->fm.scope);
						if(result == 0) {
							policyEffects[i] = Effect :: Indeterminate;
							continue;
						} else
							matcherResults[i] = result;
					}
					else
						return false;

					bool ok = pIntTokens.find("p_eft") != pIntTokens.end();
					if(ok) {
						int j = pIntTokens["p_eft"];
						string eft = pVals[j];
						if(eft == "allow")
							policyEffects[i] = Effect :: Allow;
						else if(eft == "deny")
							policyEffects[i] = Effect :: Deny;
						else
							policyEffects[i] = Effect :: Indeterminate;
					}
					else
						policyEffects[i] = Effect :: Allow;

					if(this->model.M["e"].AMap["e"]->Value == "priority(p_eft) || deny")
						break;
				}
			} else {
				this->fm.Eval(expString);
				bool result = this->fm.getBooleanResult();
				//TODO
				// log.LogPrint("Result: ", result)

				if(result)
					policyEffects[0] = Effect::Allow;
				else
					policyEffects[0] = Effect::Indeterminate;
			}

			//TODO
			// log.LogPrint("Rule Results: ", policyEffects)

			bool result = this->eft->MergeEffects(this->model.M["e"].AMap["e"]->Value, policyEffects, matcherResults);
			
			return result;
		}

		// Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
		bool Enforce() {
			return this->enforce("");
		}

		// EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
		bool EnforceWithMatcher(string matcher) {
			return this->enforce(matcher);
		}

		/*Management API member functions.*/
		vector<string> GetAllSubjects();
        vector<string> GetAllNamedSubjects(string ptype);
        vector<string> GetAllObjects();
        vector<string> GetAllNamedObjects(string ptype);
        vector<string> GetAllActions();
        vector<string> GetAllNamedActions(string ptype);
        vector<string> GetAllRoles();
        vector<string> GetAllNamedRoles(string ptype);
        vector<vector<string>> GetPolicy();
        vector<vector<string>> GetFilteredPolicy(int fieldIndex, vector<string> fieldValues);
        vector<vector<string>> GetNamedPolicy(string ptype);
        vector<vector<string>> GetFilteredNamedPolicy(string ptype, int fieldIndex, vector<string> fieldValues);
        vector<vector<string>> GetGroupingPolicy();
        vector<vector<string>> GetFilteredGroupingPolicy(int fieldIndex, vector<string> fieldValues);
        vector<vector<string>> GetNamedGroupingPolicy(string ptype);
        vector<vector<string>> GetFilteredNamedGroupingPolicy(string ptype, int fieldIndex, vector<string> fieldValues);
        bool HasPolicy(vector<string> params);
        bool HasNamedPolicy(string ptype, vector<string> params);
        bool AddPolicy(vector<string> params);
        bool AddNamedPolicy(string ptype, vector<string> params);
        bool RemovePolicy(vector<string> params);
        bool RemoveFilteredPolicy(int fieldIndex, vector<string> fieldValues);
        bool RemoveNamedPolicy(string ptype, vector<string> params);
        bool RemoveFilteredNamedPolicy(string ptype, int fieldIndex, vector<string> fieldValues);
        bool HasGroupingPolicy(vector<string> params);
        bool HasNamedGroupingPolicy(string ptype, vector<string> params);
        bool AddGroupingPolicy(vector<string> params);
        bool AddNamedGroupingPolicy(string ptype, vector<string> params);
        bool RemoveGroupingPolicy(vector<string> params);
        bool RemoveFilteredGroupingPolicy(int fieldIndex, vector<string> fieldValues);
        bool RemoveNamedGroupingPolicy(string ptype, vector<string> params);
        bool RemoveFilteredNamedGroupingPolicy(string ptype, int fieldIndex, vector<string> fieldValues);
        void AddFunction(string name, Function);

		/*RBAC API member functions.*/
		vector<string> GetRolesForUser(string name);
        vector<string> GetUsersForRole(string name);
        bool HasRoleForUser(string name, string role);
        bool AddRoleForUser(string user, string role);
        bool AddPermissionForUser(string user, vector<string> permission);
        bool DeletePermissionForUser(string user, vector<string> permission);
        bool DeletePermissionsForUser(string user);
        vector<vector<string>> GetPermissionsForUser(string user);
        bool HasPermissionForUser(string user, vector<string> permission);
        vector<string> GetImplicitRolesForUser(string name, vector<string> domain);
        vector<vector<string>> GetImplicitPermissionsForUser(string user, vector<string> domain);
        vector<string> GetImplicitUsersForPermission(vector<string> permission);
        bool DeleteRoleForUser(string user, string role);
        bool DeleteRolesForUser(string user);
        bool DeleteUser(string user);
        bool DeleteRole(string role);
        bool DeletePermission(vector<string> permission);

		/* Internal API member functions */
		bool addPolicy(string sec, string ptype, vector<string> rule);
		bool removeFilteredPolicy(string sec , string ptype , int fieldIndex , vector<string> fieldValues);
		bool removePolicy(string sec , string ptype , vector<string> rule);
		

		/* RBAC API with domains.*/
		vector<string> GetUsersForRoleInDomain(string name, string domain);
		vector<string> GetRolesForUserInDomain(string name, string domain);
		vector<vector<string>> GetPermissionsForUserInDomain(string user, string domain);
		bool AddRoleForUserInDomain(string user, string role, string domain);
		bool DeleteRoleForUserInDomain(string user, string role, string domain);

};

#endif