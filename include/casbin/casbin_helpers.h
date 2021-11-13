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
*
* This is the main file for python bindings workflow
*/

#ifndef CASBIN_CPP_CASBIN_HELPERS_H
#define CASBIN_CPP_CASBIN_HELPERS_H

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <list>
#include <future>

#include "duktape/duktape.h"
#include "duktape/duk_config.h"

namespace casbin {

    class ConfigInterface {
    public:

        virtual std::string GetString(std::string_view key) = 0;
        virtual std::vector<std::string> GetStrings(std::string_view key) = 0;
        virtual bool GetBool(std::string_view key) = 0;
        virtual int GetInt(std::string_view key) = 0;
        virtual float GetFloat(std::string_view key) = 0;
        virtual void Set(std::string_view key, const std::string& value) = 0;

    };

    class Config : public ConfigInterface {
    private:

        static const std::string DEFAULT_SECTION;
        static const std::string DEFAULT_COMMENT;
        static const std::string DEFAULT_COMMENT_SEM;
        static std::mutex mtx_lock;

        std::unordered_map<std::string, std::unordered_map<std::string, std::string>> data;

        /**
            * addConfig adds a new section->key:value to the configuration.
         */
        bool AddConfig(std::string section, const std::string& option, const std::string& value);

        void Parse(const std::string& f_name);

        void ParseBuffer(std::istream* buf);

    public:

        /**
         * NewConfig create an empty configuration representation from file.
         *
         * @param confName the path of the model file.
         * @return the constructor of Config.
         */
        static std::shared_ptr<Config> NewConfig(const std::string& conf_name);

        /**
         * newConfigFromText create an empty configuration representation from text.
         *
         * @param text the model text.
         * @return the constructor of Config.
         */
        static std::shared_ptr<Config> NewConfigFromText(const std::string& text);

        bool GetBool(std::string_view key);

        Config();

        Config(const std::string& conf_name);

        int GetInt(std::string_view key);

        float GetFloat(std::string_view key);

        std::string GetString(std::string_view key);

        std::vector<std::string> GetStrings(std::string_view key);

        void Set(std::string_view key, const std::string& value);

        std::string Get(std::string_view key);
    };


    // RoleManager provides interface to define the operations for managing roles.
    class RoleManager {
    public:
        // Clear clears all stored data and resets the role manager to the initial state.
        virtual void Clear() = 0;
        // AddLink adds the inheritance link between two roles. role: name1 and role: name2.
        // domain is a prefix to the roles (can be used for other purposes).
        virtual void AddLink(std::string name1, std::string name2, std::vector<std::string> domain = std::vector<std::string>{}) = 0;
        // DeleteLink deletes the inheritance link between two roles. role: name1 and role: name2.
        // domain is a prefix to the roles (can be used for other purposes).
        virtual void DeleteLink(std::string name1, std::string name2, std::vector<std::string> domain = std::vector<std::string>{}) = 0;
        // HasLink determines whether a link exists between two roles. role: name1 inherits role: name2.
        // domain is a prefix to the roles (can be used for other purposes).
        virtual bool HasLink(std::string name1, std::string name2, std::vector<std::string> domain = std::vector<std::string>{}) = 0;
        // GetRoles gets the roles that a user inherits.
        // domain is a prefix to the roles (can be used for other purposes).
        virtual std::vector<std::string> GetRoles(std::string name, std::vector<std::string> domain = std::vector<std::string>{}) = 0;
        // GetUsers gets the users that inherits a role.
        // domain is a prefix to the users (can be used for other purposes).
        virtual std::vector<std::string> GetUsers(std::string name, std::vector<std::string> domain = std::vector<std::string>{}) = 0;
        // PrintRoles prints all the roles to log.
        virtual void PrintRoles() = 0;
    };

    enum class Effect{
        Allow, Indeterminate, Deny
    };

    typedef enum Effect Effect;

    /**
    * Effector is the abstract class for Casbin effectors.
    */
    class Effector{
    public:
        /**
         * MergeEffects merges all matching results collected by the enforcer into a single decision.
         *
         * @param expr the expression of [policy_effect].
         * @param effects the effects of all matched rules.
         * @param results the matcher results of all matched rules.
         * @return the final effect.
         */
        virtual bool MergeEffects(std::string expr, std::vector<Effect> effects, std::vector<float> results) = 0;
    };

    enum policy_op{
        policy_add,
        policy_remove
    };

    typedef enum policy_op policy_op;

    // Assertion represents an expression in a section of the model.
    // For example: r = sub, obj, act
    class Assertion {
    public:

        std::string key;
        std::string value;
        std::vector<std::string> tokens;
        std::vector<std::vector<std::string>> policy;
        std::shared_ptr<RoleManager> rm;

        void BuildIncrementalRoleLinks(std::shared_ptr<RoleManager> rm, policy_op op, const std::vector<std::vector<std::string>>& rules);

        void BuildRoleLinks(std::shared_ptr<RoleManager> rm);
    };

    // AssertionMap is the collection of assertions, can be "r", "p", "g", "e", "m".
    class AssertionMap {
        public:

            std::unordered_map<std::string, std::shared_ptr<Assertion>> assertion_map;
    };

    // Model represents the whole access control model.
    class Model {
        private:

            static std::unordered_map<std::string, std::string> section_name_map;

            static void LoadSection(Model* raw_ptr, std::shared_ptr<ConfigInterface> cfg, const std::string& sec);

            static std::string GetKeySuffix(int i);

            static bool LoadAssertion(Model* raw_ptr, std::shared_ptr<ConfigInterface> cfg, const std::string& sec, const std::string& key);

        public:

            Model();

            Model(const std::string& path);

            std::unordered_map<std::string, AssertionMap> m;

            // Minimal required sections for a model to be valid
            static std::vector<std::string> required_sections;

            bool HasSection(const std::string& sec);

            // AddDef adds an assertion to the model.
            bool AddDef(const std::string& sec, const std::string& key, const std::string& value);

            // LoadModel loads the model from model CONF file.
            void LoadModel(const std::string& path);

            // LoadModelFromText loads the model from the text.
            void LoadModelFromText(const std::string& text);

            void LoadModelFromConfig(std::shared_ptr<Config>& cfg);

            // PrintModel prints the model to the log.
            void PrintModel();

            // NewModel creates an empty model.
            static std::shared_ptr<Model> NewModel();

            // NewModel creates a model from a .CONF file.
            static std::shared_ptr<Model> NewModelFromFile(const std::string& path);

            // NewModel creates a model from a std::string which contains model text.
            static std::shared_ptr<Model> NewModelFromString(const std::string& text);

            void BuildIncrementalRoleLinks(std::shared_ptr<RoleManager>& rm, policy_op op, const std::string& sec, const std::string& p_type, const std::vector<std::vector<std::string>>& rules);

            // BuildRoleLinks initializes the roles in RBAC.
            void BuildRoleLinks(std::shared_ptr<RoleManager>& rm);

            // PrintPolicy prints the policy to log.
            void PrintPolicy();

            // ClearPolicy clears all current policy.
            void ClearPolicy();

            // GetPolicy gets all rules in a policy.
            std::vector<std::vector<std::string>> GetPolicy(const std::string& sec, const std::string& p_type);

            // GetFilteredPolicy gets rules based on field filters from a policy.
            std::vector<std::vector<std::string>> GetFilteredPolicy(const std::string& sec, const std::string& p_type, int field_index, const std::vector<std::string>& field_values);

            // HasPolicy determines whether a model has the specified policy rule.
            bool HasPolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule);

            // AddPolicy adds a policy rule to the model.
            bool AddPolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule);

            // AddPolicies adds policy rules to the model.
            bool AddPolicies(const std::string& sec, const std::string& p_type, const std::vector<std::vector<std::string>>& rules);

            // UpdatePolicy updates a policy rule from the model.
            bool UpdatePolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule);

            // UpdatePolicies updates a set of policy rules from the model.
            bool UpdatePolicies(const std::string& sec, const std::string& p_type, const std::vector<std::vector<std::string>>& oldRules, const std::vector<std::vector<std::string>>& newRules);

            // RemovePolicy removes a policy rule from the model.
            bool RemovePolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule);

            // RemovePolicies removes policy rules from the model.
            bool RemovePolicies(const std::string& sec, const std::string& p_type, const std::vector<std::vector<std::string>>& rules);

            // RemoveFilteredPolicy removes policy rules based on field filters from the model.
            std::pair<bool, std::vector<std::vector<std::string>>> RemoveFilteredPolicy(const std::string& sec, const std::string& p_type, int field_index, const std::vector<std::string>& field_values);

            // GetValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
            std::vector<std::string> GetValuesForFieldInPolicy(const std::string& sec, const std::string& p_type, int field_index);

            // GetValuesForFieldInPolicyAllTypes gets all values for a field for all rules in a policy of all p_types, duplicated values are removed.
            std::vector<std::string> GetValuesForFieldInPolicyAllTypes(const std::string& sec, int field_index);
    };

    // LoadPolicyLine loads a text line as a policy rule to model.
    void LoadPolicyLine(std::string line, const std::shared_ptr<Model>& model);

    /**
     * Adapter is the interface for Casbin adapters.
     */
    class Adapter {
    public:

        std::string  file_path;
        bool filtered;

        /**
         * LoadPolicy loads all policy rules from the storage.
         *
         * @param model the model.
         */
        virtual void LoadPolicy(const std::shared_ptr<Model>& model) = 0;

        /**
         * SavePolicy saves all policy rules to the storage.
         *
         * @param model the model.
         */
        virtual void SavePolicy(const std::shared_ptr<Model>& model) = 0;

        /**
         * AddPolicy adds a policy rule to the storage.
         * This is part of the Auto-Save feature.
         *
         * @param sec the section, "p" or "g".
         * @param p_type the policy type, "p", "p2", .. or "g", "g2", ..
         * @param rule the rule, like (sub, obj, act).
         */
        virtual void AddPolicy(std::string sec, std::string p_type, std::vector<std::string> rule) = 0;

        /**
         * RemovePolicy removes a policy rule from the storage.
         * This is part of the Auto-Save feature.
         *
         * @param sec the section, "p" or "g".
         * @param p_type the policy type, "p", "p2", .. or "g", "g2", ..
         * @param rule the rule, like (sub, obj, act).
         */
        virtual void RemovePolicy(std::string sec, std::string p_type, std::vector<std::string> rule) = 0;

        /**
         * RemoveFilteredPolicy removes policy rules that match the filter from the storage.
         * This is part of the Auto-Save feature.
         *
         * @param sec the section, "p" or "g".
         * @param p_type the policy type, "p", "p2", .. or "g", "g2", ..
         * @param field_index the policy rule's start index to be matched.
         * @param field_values the field values to be matched, value ""
         *                    means not to match this field.
         */
        virtual void RemoveFilteredPolicy(std::string sec, std::string ptype, int field_index, std::vector<std::string> field_values) = 0;

        virtual bool IsFiltered() = 0;
    };

    // Filter defines the filtering rules for a FilteredAdapter's policy. Empty values
    // are ignored, but all others must match the filter.
    class Filter{
    public:
        std::vector<std::string> P;
        std::vector<std::string> G;
    };

    // FilteredAdapter is the interface for Casbin adapters supporting filtered policies.
    class FilteredAdapter : virtual public Adapter {
    public:

        // LoadFilteredPolicy loads only policy rules that match the filter.
        void LoadFilteredPolicy(Model* model, Filter* filter);
        // IsFiltered returns true if the loaded policy has been filtered.
        virtual bool IsFiltered() = 0;
    };

    class BatchAdapter: virtual public Adapter {
    public:

        // AddPolicies adds policy rules to the storage.
        // This is part of the Auto-Save feature.
        virtual void AddPolicies(std::string sec, std::string p_type, std::vector<std::vector<std::string>> rules) = 0;
        // RemovePolicies removes policy rules from the storage.
        // This is part of the Auto-Save feature.
        virtual void RemovePolicies(std::string sec, std::string p_type, std::vector<std::vector<std::string>> rules) = 0;
    };

    // Watcher is the interface for Casbin watchers.
    class Watcher {
    public:

        // SetUpdateCallback sets the callback function that the watcher will call
        // when the policy in DB has been changed by other instances.
        // A classic callback is Enforcer.LoadPolicy().
        template <typename Func>
        void SetUpdateCallback(Func func){
            return;
        }

        // Update calls the update callback of other instances to synchronize their policy.
        // It is usually called after changing the policy in DB, like Enforcer.SavePolicy(),
        // Enforcer.AddPolicy(), Enforcer.RemovePolicy(), etc.
        virtual void Update() = 0;

        // Close stops and releases the watcher, the callback function will not be called any more.
        virtual void Close() = 0;
    };

    class DefaultWatcher: public Watcher {
    public:

        template <typename Func>
        void SetUpdateCallback(Func func);

        void Update();

        void Close();
    };

    // WatcherEx is the strengthen for Casbin watchers.
    class WatcherEx: public Watcher {
    public:
        // UpdateForAddPolicy calls the update callback of other instances to synchronize their policy.
        // It is called after Enforcer.AddPolicy()
        virtual void UpdateForAddPolicy(std::vector<std::string> params) = 0;

        // UPdateForRemovePolicy calls the update callback of other instances to synchronize their policy.
        // It is called after Enforcer.RemovePolicy()
        virtual void UpdateForRemovePolicy(std::vector<std::string> params) = 0;

        // UpdateForRemoveFilteredPolicy calls the update callback of other instances to synchronize their policy.
        // It is called after Enforcer.RemoveFilteredNamedGroupingPolicy()
        virtual void UpdateForRemoveFilteredPolicy(int field_index, std::vector<std::string> field_values) = 0;

        // UpdateForSavePolicy calls the update callback of other instances to synchronize their policy.
        // It is called after Enforcer.RemoveFilteredNamedGroupingPolicy()
        virtual void UpdateForSavePolicy(Model* model) = 0;
    };

    class DefaultWatcherEx: public WatcherEx {
    public:

        void UpdateForAddPolicy(std::vector<std::string> params);

        void UpdateForRemovePolicy(std::vector<std::string> params);

        void UpdateForRemoveFilteredPolicy(int field_index, std::vector<std::string> field_values);

        void UpdateForSavePolicy(Model* model);
    };

    // Adapter is the file adapter for Casbin.
    // It can load policy from file or save policy to file.
    class FileAdapter : virtual public Adapter {
    public:

        // NewAdapter is the constructor for Adapter.
        FileAdapter(std::string file_path);

        static std::shared_ptr<FileAdapter> NewFileAdapter(std::string file_path);

        // LoadPolicy loads all policy rules from the storage.
        void LoadPolicy(const std::shared_ptr<Model>& model);

        // SavePolicy saves all policy rules to the storage.
        void SavePolicy(const std::shared_ptr<Model>& model);

        void LoadPolicyFile(const std::shared_ptr<Model>& model, std::function<void(std::string, const std::shared_ptr<Model>&)> handler);

        void SavePolicyFile(std::string text);

        // AddPolicy adds a policy rule to the storage.
        void AddPolicy(std::string sec, std::string p_type, std::vector<std::string> rule);

        // RemovePolicy removes a policy rule from the storage.
        void RemovePolicy(std::string sec, std::string p_type, std::vector<std::string> rule);

        // RemoveFilteredPolicy removes policy rules that match the filter from the storage.
        void RemoveFilteredPolicy(std::string sec, std::string p_type, int field_index, std::vector<std::string> field_values);

        // IsFiltered returns true if the loaded policy has been filtered.
        bool IsFiltered();
    };

    class BatchFileAdapter: public BatchAdapter, public FileAdapter {
    public:

        // NewAdapter is the constructor for Adapter.
        BatchFileAdapter(std::string file_path);

        static std::shared_ptr<BatchFileAdapter> NewBatchFileAdapter(std::string file_path);

        void AddPolicies(std::string sec, std::string p_type, std::vector<std::vector<std::string>> rules);

        void RemovePolicies(std::string sec, std::string p_type, std::vector<std::vector<std::string>> rules);
    };

    class FilteredFileAdapter : public FileAdapter, public FilteredAdapter {
    private:

        static bool filterLine(std::string line, Filter* filter);

        static bool filterWords(std::vector<std::string> line, std::vector<std::string> filter);

        void loadFilteredPolicyFile(Model* model, Filter* filter, void (*handler)(std::string, Model*));

    public:

        // NewFilteredAdapter is the constructor for FilteredAdapter.
        FilteredFileAdapter(std::string file_path);

        // LoadPolicy loads all policy rules from the storage.
        void LoadPolicy(Model* model);

        // LoadFilteredPolicy loads only policy rules that match the filter.
        void LoadFilteredPolicy(Model* model, Filter* filter);

        // IsFiltered returns true if the loaded policy has been filtered.
        bool IsFiltered();

        // SavePolicy saves all policy rules to the storage.
        void SavePolicy(Model* model);
    };

#define VARARGS DUK_VARARGS
#define RETURN_RESULT 1

    enum Type{
        Bool, Float
    };

    typedef duk_context* Scope;
    typedef duk_context PScope;
    typedef duk_ret_t ReturnType;
    typedef duk_c_function Function;
    typedef duk_idx_t Index;

    Scope InitializeScope();
    void DeinitializeScope(Scope scope);
    void PushFunctionValue(Scope scope, Function f, int nargs);
    void PushBooleanValue(Scope scope, bool expression);
    void PushTrueValue(Scope scope);
    void PushFalseValue(Scope scope);
    void PushIntValue(Scope scope, int integer);
    void PushFloatValue(Scope scope, float f);
    void PushDoubleValue(Scope scope, double d);
    void PushStringValue(Scope scope, std::string s);
    void PushPointerValue(Scope scope, void * ptr);
    void PushObjectValue(Scope scope);
    void PushFunction(Scope scope, Function f, std::string fname, int nargs);
    void PushBoolean(Scope scope, bool expression, std::string identifier);
    void PushTrue(Scope scope, std::string identifier);
    void PushFalse(Scope scope, std::string identifier);
    void PushInt(Scope scope, int integer, std::string identifier);
    void PushFloat(Scope scope, float f, std::string identifier);
    void PushDouble(Scope scope, double d, std::string identifier);
    void PushString(Scope scope, std::string s, std::string identifier);
    void PushPointer(Scope scope, void * ptr, std::string identifier);
    void PushObject(Scope scope, std::string identifier = "r");
    void PushFunctionPropToObject(Scope scope, std::string obj, Function f, std::string fname, int nargs);
    void PushBooleanPropToObject(Scope scope, std::string obj, bool expression, std::string identifier);
    void PushTruePropToObject(Scope scope, std::string obj, std::string identifier);
    void PushFalsePropToObject(Scope scope, std::string obj, std::string identifier);
    void PushIntPropToObject(Scope scope, std::string obj, int integer, std::string identifier);
    void PushFloatPropToObject(Scope scope, std::string obj, float f, std::string identifier);
    void PushDoublePropToObject(Scope scope, std::string obj, double d, std::string identifier);
    void PushStringPropToObject(Scope scope, std::string obj, std::string s, std::string identifier);
    void PushPointerPropToObject(Scope scope, std::string obj, void * ptr, std::string identifier);
    void PushObjectPropToObject(Scope scope, std::string obj, std::string identifier);
    void PushObjectPropFromJson(Scope scope, nlohmann::json& j, std::string j_name);
    Type CheckType(Scope scope);
    bool FetchIdentifier(Scope scope, std::string identifier);
    unsigned int Size(Scope scope);
    bool GetBoolean(Scope scope, int id = -1);
    int GetInt(Scope scope, int id = -1);
    float GetFloat(Scope scope, int id = -1);
    double GetDouble(Scope scope, int id = -1);
    std::string GetString(Scope scope, int id = -1);
    void* GetPointer(Scope scope, int id = -1);
    void Get(Scope scope, std::string identifier);
    bool Eval(Scope scope, std::string expression);
    void EvalNoResult(Scope scope, std::string expression);


    // KeyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
    // For example, "/foo/bar" matches "/foo/*"
    ReturnType KeyMatch(Scope scope);
    bool KeyMatch(const std::string& key1, const std::string& key2);
    
    // KeyMatch2 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
    // For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource"
    ReturnType KeyMatch2(Scope scope);
    bool KeyMatch2(const std::string& key1, const std::string& key2);
    
    // KeyMatch3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
    // For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}"
    ReturnType KeyMatch3(Scope scope);
    bool KeyMatch3(const std::string& key1, const std::string& key2);
    
    // RegexMatch determines whether key1 matches the pattern of key2 in regular expression.
    ReturnType RegexMatch(Scope scope);
    bool RegexMatch(const std::string& key1, const std::string& key2);
    
    // IPMatch determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
    // For example, "192.168.2.123" matches "192.168.2.0/24"
    ReturnType IPMatch(Scope scope);
    bool IPMatch(const std::string& ip1, const std::string& ip2);
    
    // GFunction is the method of the g(_, _) function.
    ReturnType GFunction(Scope scope);

    // IPMatch determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
    // For example, "192.168.2.123" matches "192.168.2.0/24"
    ReturnType IPMatch(Scope scope);
    bool IPMatch(std::string ip1, std::string ip2);

    // GFunction is the method of the g(_, _) function.
    ReturnType GFunction(Scope scope);

    // ArrayEquals determines whether two std::string arrays are identical.
    bool ArrayEquals(std::vector<std::string> a, std::vector<std::string> b);

    // ArrayRemoveDuplicates removes any duplicated elements in a std::string array.
    void ArrayRemoveDuplicates(std::vector<std::string>& s);

    std::string ArrayToString(const std::vector<std::string>& arr);

    bool EndsWith(std::string_view base, std::string_view suffix);

    /**
    * escapeAssertion escapes the dots in the assertion, because the expression evaluation doesn't support such variable names.
    *
    * @param s the value of the matcher and effect assertions.
    * @return the escaped value.
    */
    std::string EscapeAssertion(std::string s);

    std::vector<size_t> FindAllOccurences(std::string_view data, std::string_view toSearch);

    template<typename Base, typename T>
    bool IsInstanceOf(const T*);

    std::vector<std::string> JoinSlice(const std::string& a, const std::vector<std::string>& slice);

    std::string Join(const std::vector<std::string>& vos, const std::string& sep = " ");

    // RemoveComments removes the comments starting with # in the text.
    std::string RemoveComments(std::string_view s);

    // SetSubtract returns the elements in `a` that aren't in `b`.
    std::vector<std::string> SetSubtract(const std::vector<std::string>& a, const std::vector<std::string>& b);

    std::vector<std::string> Split(std::string str, std::string del, int limit = 0);

    std::string& LTrim(std::string& str, const std::string& chars = "\t\n\v\f\r ");

    std::string& RTrim(std::string& str, const std::string& chars = "\t\n\v\f\r ");

    std::string Trim(std::string& str, const std::string& chars = "\t\n\v\f\r ");

    // Exception class for Casbin Adapter Exception.
    class CasbinAdapterException : std::logic_error {
    public:
        using std::logic_error::logic_error;
    };

    // Exception class for Casbin Enforcer Exception.
    class CasbinEnforcerException : std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    // Exception class for Casbin Adapter Exception.
    class CasbinRBACException : std::invalid_argument {
    public:
        using std::invalid_argument::invalid_argument;
    };

    // Exception class for illegal arguments.
    class IllegalArgumentException : std::invalid_argument {
    public:
        using std::invalid_argument::invalid_argument;
    };

    // Exception class for I/O operations.
    class IOException : std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    // Exception class for missing required sections.
    class MissingRequiredSections : std::domain_error {
    public:
        using std::domain_error::domain_error;
    };

    // Exception class for unsupported operations.
    class UnsupportedOperationException : std::logic_error {
    public:
        using std::logic_error::logic_error;
    };

    typedef bool (*MatchingFunc)(const std::string&, const std::string&);

    /**
    * Role represents the data structure for a role in RBAC.
    */
    class Role {
    
    private:
        std::vector<Role*> roles;

    public:
        std::string name;

        static Role* NewRole(std::string name);
        
        void AddRole(Role* role);

        void DeleteRole(Role* role);

        bool HasRole(std::string name, int hierarchy_level);

        bool HasDirectRole(std::string name);

        std::string ToString();

        std::vector<std::string> GetRoles();
    };

    class DefaultRoleManager : public RoleManager {
    private:
        std::unordered_map<std::string, Role*> all_roles;
        bool has_pattern;
        int max_hierarchy_level;
        MatchingFunc matching_func;

        bool HasRole(std::string name);

        Role* CreateRole(std::string name);

    public:

        /**
         * DefaultRoleManager is the constructor for creating an instance of the
         * default RoleManager implementation.
         *
         * @param max_hierarchy_level the maximized allowed RBAC hierarchy level.
         */
        DefaultRoleManager(int max_hierarchy_level);

        // e.BuildRoleLinks must be called after AddMatchingFunc().
        //
        // example: e.GetRoleManager().(*defaultrolemanager.RoleManager).AddMatchingFunc('matcher', util.KeyMatch)
        void AddMatchingFunc(MatchingFunc fn);

        /**
         * clear clears all stored data and resets the role manager to the initial state.
         */
        void Clear();

        // AddLink adds the inheritance link between role: name1 and role: name2.
        // aka role: name1 inherits role: name2.
        // domain is a prefix to the roles.
        void AddLink(std::string name1, std::string name2, std::vector<std::string> domain = {});

        /**
         * deleteLink deletes the inheritance link between role: name1 and role: name2.
         * aka role: name1 does not inherit role: name2 any more.
         * domain is a prefix to the roles.
         */
        void DeleteLink(std::string name1, std::string name2, std::vector<std::string> domain = {});

        /**
         * hasLink determines whether role: name1 inherits role: name2.
         * domain is a prefix to the roles.
         */
        bool HasLink(std::string name1, std::string name2, std::vector<std::string> domain = {});

        /**
         * getRoles gets the roles that a subject inherits.
         * domain is a prefix to the roles.
         */
        std::vector<std::string> GetRoles(std::string name, std::vector<std::string> domain = {});

        std::vector<std::string> GetUsers(std::string name, std::vector<std::string> domain = {});

        /**
         * printRoles prints all the roles to log.
         */
        void PrintRoles();
    };

    class FunctionMap {
    public:
        Scope scope;
        std::list<std::string> func_list;

        FunctionMap();

        void ProcessFunctions(const std::string& expression);

        int GetRLen();

        bool Evaluate(const std::string& expression);

        bool GetBooleanResult();

        // AddFunction adds an expression function.
        void AddFunction(const std::string& func_name, Function f, Index nargs);

        void AddFunctionPropToR(const std::string& identifier, Function func, Index nargs);

        void AddBooleanPropToR(const std::string& identifier, bool val);

        void AddTruePropToR(const std::string& identifier);

        void AddFalsePropToR(const std::string& identifier);

        void AddIntPropToR(const std::string& identifier, int val);

        void AddFloatPropToR(const std::string& identifier, float val);

        void AddDoublePropToR(const std::string& identifier, double val);

        void AddStringPropToR(const std::string& identifier, const std::string& val);

        void AddPointerPropToR(const std::string& identifier, void* val);

        void AddObjectPropToR(const std::string& identifier);

        // LoadFunctionMap loads an initial function map.
        void LoadFunctionMap();

    };

    class Logger{
    protected:
        bool m_enable;

    public:

        //EnableLog controls whether print the message.
        virtual void EnableLog(bool enable) = 0;

        //IsEnabled returns if logger is enabled.
        virtual bool IsEnabled() = 0;

        //Print formats using the default formats for its operands and logs the message.
        template <typename T, typename... Object>
        void Print(T arg, Object... objects);

        //Printf formats according to a format specifier and logs the message.
        template <typename... Object>
        void Printf(std::string, Object... objects);
    };

    class DefaultLogger : public Logger {
    public:

        void EnableLog(bool enable) {
            m_enable = enable;
        }

        bool IsEnabled() {
            return m_enable;
        }

        template <typename... Object>
        void Print(Object... objects){
            if (m_enable){
                Print(objects...);
            }
        }

        template <typename... Object>
        void Print(std::string format, Object... objects){
            if (m_enable){
                Printf(format, objects...);
            }
        }
    };

    class LogUtil {
    private:
        static DefaultLogger s_logger;
    public:

        // SetLogger sets the current logger.
        static void SetLogger(const DefaultLogger& l){
            s_logger = l;
        }

        // GetLogger returns the current logger.
        static DefaultLogger GetLogger() {
            return s_logger;
        }

        // LogPrint prints the log.
        template <typename... Object>
        static void LogPrint(Object... objects) {
            s_logger.Print(objects...);
        }

        // LogPrintf prints the log with the format.
        template <typename... Object>
        static void LogPrintf(std::string format, Object... objects) {
            s_logger.Printf(format, objects...);
        }
    };

    class Ticker {
    public:
        typedef std::chrono::duration<int64_t, std::nano> tick_interval_t;
        typedef std::function<void()> on_tick_t;
        typedef std::vector<std::future<void>> future_vec;

        Ticker(std::function<void()> onTick, std::chrono::duration<int64_t, std::nano> tickInterval);

        ~Ticker();

        void start();

        void stop();

    private:
        void timer_loop();
        on_tick_t           _onTick;
        tick_interval_t     _tickInterval;
        std::atomic_bool    _running;
        std::mutex          _tickIntervalMutex;
        future_vec          _futures1;
        future_vec          _futures2;
    };

} // namespace casbin

#endif //CASBIN_CPP_CASBIN_HELPERS_H
