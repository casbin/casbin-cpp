#ifndef ABAC_H
#define ABAC_H

#include <unordered_map>
#include <string>
#include <vector>
#include <variant>
#include <memory>

namespace casbin {

/**
 * @brief A wrapper to contain ABAC entity with a list of attributes stored in a hashmap
 * 
 */
class ABACData {

public:
// Array containing the reference to instantiated ABACData so far
static std::vector<std::shared_ptr<ABACData>> s_dataSet;

private:

    // Intrinsic definitions
    typedef std::variant<std::string, int32_t, float> VariantType;
    typedef std::unordered_map<std::string, VariantType> VariantMap;

    // HashMap containing attributes as key-value pairs
    VariantMap m_attributes;

public:
    /**
     * @brief Construct a new casbin::ABACData object
     * 
     * @param attribs Should be of the format: {
     * { "attrib_name1", "value1" },
     * { "attring_name2", "value2" },
     * ...
     * }
     * 
     * Key's type is std::string and value's type can be one of std::string, int32_t, and float only
     */
    ABACData(const VariantMap& attribs);
    /**
     * @brief Add attribute to the corresponding ABAC entity
     * 
     * @param key Name of the attribute
     * @param value Value of the attribute
     * @return true when attribute is added successfully, false otherwise
     */
    bool AddAttribute(const std::string& key, const VariantType& value);
    /**
     * @brief Add attributes to the corresponding ABAC entity
     * 
     * @param attribs Should be of the format: {
     * { "attrib_name1", "value1" },
     * { "attring_name2", "value2" },
     * ...
     * }
     * 
     * Key's type is std::string and value's type can be one of std::string, int32_t, and float only
     * @return true if attributes are added successfully, false otherwise
     */
    bool AddAttributes(const VariantMap& attribs);
    /**
     * @brief Delete attribute of the corresponding ABAC entity
     * 
     * @param key Name of the attribute to be deleted
     * @return true when attribute is deleted successfully, false otherwise
     */
    bool DeleteAttribute(const std::string& key);
    /**
     * @brief Update attribute of the corresponding ABAC entity
     * 
     * @param key Name of the attribute to be updated
     * @param value Value which would replace the current value of the attribute corresponding 
     * to the given key
     * @return true 
     * @return false 
     */
    bool UpdateAttribute(const std::string& key, const VariantType& value);
    /**
     * @brief Get the Attributes of the corresponding ABAC entity
     * 
     * @return const reference to the hashmap containing attributes in key-value pairs
     */
    const VariantMap& GetAttributes();
};

// Casbin ABAC entity type
typedef ABACData ABACData;

}

#endif
