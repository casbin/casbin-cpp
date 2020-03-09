#ifndef CASBIN_CPP_CONFIG_CONFIG_INTERFACE
#define CASBIN_CPP_CONFIG_CONFIG_INTERFACE

#include <string>
#include <vector>

#endif

using namespace std;

class ConfigInterface {

    public:

        virtual string getString(string key) = 0;
        virtual vector <string> getStrings(string key) = 0;
        virtual bool getBool(string key) = 0;
        virtual int getInt(string key) = 0;
        virtual float getFloat(string key) = 0;
        virtual void set(string key,string value) = 0;

};