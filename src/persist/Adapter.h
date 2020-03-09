#ifndef CASBIN_CPP_PERSIST_ADAPTER
#define CASBIN_CPP_PERSIST_ADAPTER

#include <string>
#include <vector>

#include "../model/Model.h"

#endif

using namespace std;

/**
 * Adapter is the interface for Casbin adapters.
 */
class Adapter {
    /**
     * loadPolicy loads all policy rules from the storage.
     *
     * @param model the model.
     */
    virtual void loadPolicy(Model model);

    /**
     * savePolicy saves all policy rules to the storage.
     *
     * @param model the model.
     */
    virtual void savePolicy(Model model);

    /**
     * addPolicy adds a policy rule to the storage.
     * This is part of the Auto-Save feature.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule the rule, like (sub, obj, act).
     */
    virtual void addPolicy(string sec, string ptype, vector<string> rule);

    /**
     * removePolicy removes a policy rule from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule the rule, like (sub, obj, act).
     */
    virtual void removePolicy(string sec, string ptype, vector<string> rule);

    /**
     * removeFilteredPolicy removes policy rules that match the filter from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param sec the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     */
    template <typename... Strings>
    void removeFilteredPolicy(string sec, string ptype, int fieldIndex, Strings... fieldValues);
};
