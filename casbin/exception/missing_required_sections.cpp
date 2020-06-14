#pragma once

#include "pch.h"

#include "./missing_required_sections.h"

MissingRequiredSections :: MissingRequiredSections(string error_message) {
    this->error_message = error_message;
}