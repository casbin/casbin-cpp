#include "pch.h"

#ifndef BATCH_FILE_ADAPTER_CPP
#define BATCH_FILE_ADAPTER_CPP


#include "./batch_file_adapter.h"
#include "../../exception/unsupported_operation_exception.h"

namespace casbin {

// NewAdapter is the constructor for Adapter.
BatchFileAdapter::BatchFileAdapter(std::string file_path): FileAdapter(file_path) {
}

void BatchFileAdapter::AddPolicies(std::string sec, std::string p_type, std::vector<std::vector<std::string>> rules) {
    throw UnsupportedOperationException("not implemented hello");
}

void BatchFileAdapter::RemovePolicies(std::string sec, std::string p_type, std::vector<std::vector<std::string>> rules) {
    throw UnsupportedOperationException("not implemented");
}

} // namespace casbin

#endif // BATCH_FILE_ADAPTER_CPP
