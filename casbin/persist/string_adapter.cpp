#include "casbin/pch.h"

#ifndef STRING_ADAPTER_CPP
#define STRING_ADAPTER_CPP

#include <fstream>

#include "casbin/exception/casbin_adapter_exception.h"
#include "casbin/exception/io_exception.h"
#include "casbin/exception/unsupported_operation_exception.h"
#include "casbin/persist/string_adapter.h"
#include "casbin/util/util.h"

namespace casbin {

// NewAdapter is the constructor for Adapter.
StringAdapter ::StringAdapter(std::string line) {
    this->line = line;
    this->filtered = false;
}

std::shared_ptr<casbin::StringAdapter> StringAdapter::NewStringAdapter(std::string line) {
    return std::make_shared<StringAdapter>(line);
}

// LoadPolicy loads all policy rules from the string buffer.
void StringAdapter ::LoadPolicy(const std::shared_ptr<Model>& model) {
    if (this->line == "")
        throw CasbinAdapterException("Invalid line, line cannot be empty");

    std::vector<std::string> strs = Split(this->line, "\n", -1);
    for (int i = 0; i < strs.size(); i++)
        LoadPolicyLine(strs[i], model);
}

// SavePolicy saves all policy rules to the string buffer.
void StringAdapter ::SavePolicy(const std::shared_ptr<Model>& model) {
    if (this->line == "") {
        throw CasbinAdapterException("Invalid line, line cannot be empty");
    }

    std::string tmp;

    for (std::unordered_map<std::string, std::shared_ptr<Assertion>>::iterator it = model->m["p"].assertion_map.begin(); it != model->m["p"].assertion_map.end(); it++) {
        for (int i = 0; i < it->second->policy.size(); i++) {
            tmp += it->first + ", ";
            tmp += ArrayToString(it->second->policy[i]);
            tmp += "\n";
        }
    }

    for (std::unordered_map<std::string, std::shared_ptr<Assertion>>::iterator it = model->m["g"].assertion_map.begin(); it != model->m["g"].assertion_map.end(); it++) {
        for (int i = 0; i < it->second->policy.size(); i++) {
            tmp += it->first + ", ";
            tmp += ArrayToString(it->second->policy[i]);
            tmp += "\n";
        }
    }

    this->line = RTrim(tmp, "\n");
}

// AddPolicy adds a policy rule to the string buffer.
void StringAdapter ::AddPolicy(std::string sec, std::string p_type, std::vector<std::string> rule) {
    throw UnsupportedOperationException("not implemented");
}

// RemovePolicy removes a policy rule from the string buffer.
void StringAdapter ::RemovePolicy(std::string sec, std::string p_type, std::vector<std::string> rule) {
    this->line = "";
}

// RemoveFilteredPolicy removes policy rules that match the filter from the string buffer.
void StringAdapter ::RemoveFilteredPolicy(std::string sec, std::string p_type, int field_index, std::vector<std::string> field_values) {
    throw UnsupportedOperationException("not implemented");
}

// IsFiltered returns true if the loaded policy has been filtered.
bool StringAdapter ::IsFiltered() {
    return this->filtered;
}

// IsValid returns true if the loaded policy is valid.
bool StringAdapter ::IsValid() {
    return this->line != "";
}

} // namespace casbin

#endif // STRING_ADAPTER_CPP
