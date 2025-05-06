project('casbin-cpp', 'cpp',
    version: '1.53.2',
    default_options: ['cpp_std=c++17']
)

# Include directories
inc = include_directories('include')

# Source files
casbin_sources = [
    'casbin/enforcer.cpp',
    'casbin/enforcer_cached.cpp',
    'casbin/enforcer_synced.cpp',
    'casbin/selected_policies.cpp',
    'casbin/internal_api.cpp',
    'casbin/logger.cpp',
    'casbin/management_api.cpp',
    'casbin/pch.cpp',
    'casbin/rbac_api.cpp',
    'casbin/rbac_api_with_domains.cpp',
    'casbin/config/config.cpp',
    'casbin/effect/default_effector.cpp',
    'casbin/ip_parser/exception/parser_exception.cpp',
    'casbin/ip_parser/parser/allFF.cpp',
    'casbin/ip_parser/parser/CIDRMask.cpp',
    'casbin/ip_parser/parser/dtoi.cpp',
    'casbin/ip_parser/parser/equal.cpp',
    'casbin/ip_parser/parser/IP.cpp',
    'casbin/ip_parser/parser/IPNet.cpp',
    'casbin/ip_parser/parser/IPv4.cpp',
    'casbin/ip_parser/parser/parseCIDR.cpp',
    'casbin/ip_parser/parser/parseIP.cpp',
    'casbin/ip_parser/parser/parseIPv4.cpp',
    'casbin/ip_parser/parser/parseIPv6.cpp',
    'casbin/ip_parser/parser/Print.cpp',
    'casbin/ip_parser/parser/xtoi.cpp',
    'casbin/model/assertion.cpp',
    'casbin/model/function.cpp',
    'casbin/model/model.cpp',
    'casbin/model/evaluator.cpp',
    'casbin/model/policy_collection.cpp',
    'casbin/persist/file_adapter/batch_file_adapter.cpp',
    'casbin/persist/file_adapter/file_adapter.cpp',
    'casbin/persist/file_adapter/filtered_file_adapter.cpp',
    'casbin/persist/adapter.cpp',
    'casbin/persist/default_watcher.cpp',
    'casbin/persist/default_watcher_ex.cpp',
    'casbin/persist/string_adapter.cpp',
    'casbin/rbac/default_role_manager.cpp',
    'casbin/util/array_equals.cpp',
    'casbin/util/array_remove_duplicates.cpp',
    'casbin/util/array_to_string.cpp',
    'casbin/util/built_in_functions.cpp',
    'casbin/util/ends_with.cpp',
    'casbin/util/escape_assertion.cpp',
    'casbin/util/find_all_occurences.cpp',
    'casbin/util/is_instance_of.cpp',
    'casbin/util/join.cpp',
    'casbin/util/join_slice.cpp',
    'casbin/util/remove_comments.cpp',
    'casbin/util/set_subtract.cpp',
    'casbin/util/split.cpp',
    'casbin/util/ticker.cpp',
    'casbin/util/trim.cpp',
    'casbin/util/eval.cpp'
]

# Dependencies
json_dep = dependency('nlohmann_json', fallback: ['json', 'nlohmann_json_dep'])

# Create the library
casbin_lib = static_library('casbin',
    casbin_sources,
    include_directories: inc,
    dependencies: [json_dep],
    cpp_args: ['-DNDEBUG']
)

# Create a dependency for other projects to use
casbin_cpp_dep = declare_dependency(
    link_with: casbin_lib,
    include_directories: inc,
    dependencies: [json_dep]
)
