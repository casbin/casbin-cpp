#include "casbin/pch.h"

#ifndef BATCH_FILE_ADAPTER_CPP
#define BATCH_FILE_ADAPTER_CPP

#include "casbin/exception/unsupported_operation_exception.h"
#include "casbin/persist/file_adapter/batch_file_adapter.h"

namespace casbin {

// NewAdapter is the constructor for Adapter.
BatchFileAdapter ::BatchFileAdapter(std::string file_path)
    : FileAdapter(file_path) {
}

std::shared_ptr<BatchFileAdapter> BatchFileAdapter ::NewBatchFileAdapter(std::string file_path) {
    return std::make_shared<BatchFileAdapter>(file_path);
}

void BatchFileAdapter ::AddPolicies(std::string sec, std::string p_type, PoliciesValues rules) {
    throw UnsupportedOperationException("not implemented hello");
}

void BatchFileAdapter ::RemovePolicies(std::string sec, std::string p_type, PoliciesValues rules) {
    throw UnsupportedOperationException("not implemented");
}

} // namespace casbin

#endif // BATCH_FILE_ADAPTER_CPP
