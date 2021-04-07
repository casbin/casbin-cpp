#include "pch.h"

#ifndef MISSING_REQUIRED_SECTIONS_CPP
#define MISSING_REQUIRED_SECTIONS_CPP


#include "./missing_required_sections.h"

namespace casbin {

MissingRequiredSections :: MissingRequiredSections(std::string error_message) {
    this->error_message = error_message;
}

} // namespace casbin

#endif // MISSING_REQUIRED_SECTIONS_CPP
