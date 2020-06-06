#ifndef CASBIN_CPP_CONFIG_CONFIG_INTERFACE
#define CASBIN_CPP_CONFIG_CONFIG_INTERFACE

#include <string>
#include <vector>

using namespace std;

class ConfigInterface {
    public:

        virtual string GetString(string key) = 0;
        virtual vector <string> GetStrings(string key) = 0;
        virtual bool GetBool(string key) = 0;
        virtual int GetInt(string key) = 0;
        virtual float GetFloat(string key) = 0;
        virtual void Set(string key, string value) = 0;

};

#endif