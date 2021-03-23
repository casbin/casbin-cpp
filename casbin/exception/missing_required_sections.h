#ifndef CASBIN_CPP_EXCEPTION_MISSING_REQUIRED_SECTIONS
#define CASBIN_CPP_EXCEPTION_MISSING_REQUIRED_SECTIONS

#include <string>

using namespace std;

// Exception class for missing required sections.
class MissingRequiredSections{
    string error_message;
    public:
        explicit MissingRequiredSections(string& error_message);
        explicit MissingRequiredSections(const char* error_message);
        explicit MissingRequiredSections(const string& erro_message);
};

#endif