//
// Created by Yash Pandey on 08/08/21.
//

#ifndef CASBIN_CPP_CASBIN_TYPES_H
#define CASBIN_CPP_CASBIN_TYPES_H

#include <variant>
#include <vector>
#include <initializer_list>
#include <unordered_map>

namespace casbin {

    typedef std::variant<std::string, int32_t, float, double> AttributeValue;
    typedef std::pair<std::string, AttributeValue> Attribute;
    typedef std::vector<Attribute> AttributeVector;
    typedef std::initializer_list<Attribute> AttributeList;
    typedef std::unordered_map<std::string, AttributeValue> AttributeMap;

    /**
     * @brief A wrapper to contain ABAC entity with a list of attributes stored in a hashmap
     *
     */
//    class ABACData {
//
//    private:
//
//        // HashMap containing attributes as key-value pairs
//        AttributeMap m_attributes;
//
//    public:
//        /**
//         * @brief Construct a new casbin::ABACData object
//         *
//         * @param attribs Should be of the format: {
//         * { "attrib_name1", value1 },
//         * { "attring_name2", value2 },
//         * ...
//         * }
//         *
//         * Key's type is std::string and value's type can be one of std::string, int32_t, and float only
//         */
//        ABACData(const AttributeMap& attribs);
//        /**
//         * @brief Add attribute to the corresponding ABAC entity
//         *
//         * @param key Name of the attribute
//         * @param value Value of the attribute
//         * @return true when attribute is added successfully, false otherwise
//         */
//        bool AddAttribute(const std::string& key, const AttributeValue& value);
//        /**
//         * @brief Add attributes to the corresponding ABAC entity
//         *
//         * @param attribs Should be of the format: {
//         * { "attrib_name1", value1 },
//         * { "attring_name2", value2 },
//         * ...
//         * }
//         *
//         * Key's type is std::string and value's type can be one of std::string, int32_t, and float only
//         * @return true if attributes are added successfully, false otherwise
//         */
//        bool AddAttributes(const AttributeList& attribs);
//        /**
//         * @brief Delete attribute of the corresponding ABAC entity
//         *
//         * @param key Name of the attribute to be deleted
//         * @return true when attribute is deleted successfully, false otherwise
//         */
//        bool DeleteAttribute(const std::string& key);
//        /**
//         * @brief Update attribute of the corresponding ABAC entity
//         *
//         * @param key Name of the attribute to be updated
//         * @param value Value which would replace the current value of the attribute corresponding
//         * to the given key
//         * @return true
//         * @return false
//         */
//        bool UpdateAttribute(const std::string& key, const AttributeValue& value);
//        /**
//         * @brief Get the Attributes of the corresponding ABAC entity
//         *
//         * @return const reference to the hashmap containing attributes in key-value pairs
//         */
//        const AttributeMap& GetAttributes();
//    };

    // Casbin ABAC entity type
    typedef ABACData ABACData;

    /**
     * @brief Get casbin::ABACData object
     *
     * @param attribs Should be of the format: {
     * { "attrib_name1", value1 },
     * { "attrib_name2", value2 },
     * ...
     * }
     *
     * Key's type is std::string and value's type can be one of std::string, int32_t, double, and float only
     * @return Pointer to casbin::ABACData entity
     */
    const std::shared_ptr<ABACData> GetDataObject(const AttributeMap& attribs);

    typedef std::variant<std::string, std::shared_ptr<ABACData>> Data;
    typedef std::vector<Data> DataVector;
    typedef std::initializer_list<Data> DataList;
    typedef std::unordered_map<std::string, Data> DataMap;

} // namespace casbin


#endif //CASBIN_CPP_CASBIN_TYPES_H
