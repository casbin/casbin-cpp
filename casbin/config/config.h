#pragma once

#ifdef CASBIN_EXPORTS
#define CONFIG_API __declspec(dllexport)
#else
#define CONFIG_API __declspec(dllimport)
#endif

#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

// DEFAULT_SECTION specifies the name of a section if no name provided
extern const string DEFAULT_SECTION;
// DEFAULT_COMMENT defines what character(s) indicate a comment `#`
extern const string DEFAULT_COMMENT;
// DEFAULT_COMMENT_SEM defines what alternate character(s) indicate a comment `;`
extern const string DEFAULT_COMMENT_SEM;
// DEFAULT_MULTI_LINE_SEPARATOR defines what character indicates a multi-line content
extern const string DEFAULT_MULTI_LINE_SEPARATOR;

// Config represents an implementation of the ConfigInterface
class CONFIG_API Config {
private:
    // Section:key=value
    map<string, map<string, string>> data;
    void parseFile(const string& fname);
    void parseText(const string& text);
    void parseBuffer(stringstream& buf);
    void write(const string& section, const int& lineNum, string& buffer);
    string get(const string& key);

public:
    // Config create an empty configuration without params
    Config();
    // NewConfigFromFile create an empty configuration representation from file.
    static Config NewConfigFromFile(const string& path);
    // NewConfigFromText create an empty configuration representation from text.
    static Config NewConfigFromText(const string& text);
    // AddConfig adds a new section->key:value to the configuration.
    bool AddConfig(const string& section, const string& option, const string& value);
    // Bool lookups up the value using the provided keyand converts the value to a bool
    bool Bool(const string& key);
    // Int lookups up the value using the provided key and converts the value to a int
    int Int(const string& key);
    // Long lookups up the value using the provided key and converts the value to a long
    long Long(const string& key);
    // Double lookups up the value using the provided key and converts the value to a double
    double Double(const string& key);
    // String lookups up the value using the provided key and converts the value to a string
    string String(const string& key);
    // Strings lookups up the value using the provided key and converts the value to an array of string by splitting the string by comma
    vector<string> Strings(const string& key);
    // Set sets the value for the specific key in the Config
    void Set(const string& key, const string& value);
};