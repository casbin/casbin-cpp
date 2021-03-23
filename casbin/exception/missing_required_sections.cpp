#include "pch.h"

#ifndef MISSING_REQUIRED_SECTIONS_CPP
#define MISSING_REQUIRED_SECTIONS_CPP


#include "./missing_required_sections.h"

MissingRequiredSections :: MissingRequiredSections(string& error_message):error_message(error_message) {
}

MissingRequiredSections :: MissingRequiredSections(const char *error_message):error_message(error_message) {

}

MissingRequiredSections :: MissingRequiredSections(const string& error_message):error_message(error_message) {
    
}

#endif // MISSING_REQUIRED_SECTIONS_CPP
