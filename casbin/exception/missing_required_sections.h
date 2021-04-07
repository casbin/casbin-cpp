#ifndef CASBIN_CPP_EXCEPTION_MISSING_REQUIRED_SECTIONS
#define CASBIN_CPP_EXCEPTION_MISSING_REQUIRED_SECTIONS

#include <string>

namespace casbin {

// Exception class for missing required sections.
class MissingRequiredSections{
    std::string error_message;
    public:
        MissingRequiredSections(std::string error_message);
};

} // namespace casbin

#endif