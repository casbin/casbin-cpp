/*
* Copyright 2021 The casbin Authors. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* This is the main file for python bindings workflow
*/

#ifndef CASBIN_CPP_CASBIN_H
#define CASBIN_CPP_CASBIN_H

#include "enforcer.h"
#include "enforcer_cached.h"
#include "enforcer_interface.h"
#include "enforcer_synced.h"
#include "casbin_types.h"
#include "enforcer_cached.h"

#include "pch.h"
// persist
#include "persist/batch_adapter.h"
#include "persist/watcher.h"
#include "persist/filtered_adapter.h"
#include "persist/adapter.h"
#include "persist/watcher_ex.h"
#include "persist/default_watcher_ex.h"
#include "persist/default_watcher.h"
#include "persist/persist.h"

// persist/file_adapter
#include "persist/file_adapter/file_adapter.h"
#include "persist/file_adapter/batch_file_adapter.h"
#include "persist/file_adapter/filtered_file_adapter.h"
#include "persist/watcher_update.h"

// effect
#include "effect/effector.h"
#include "effect/default_effector.h"
#include "effect/effect.h"

// ip_parser
// ip_parser/exception
#include "ip_parser/exception/parser_exception.h"
// ip_parser/parser
#include "ip_parser/parser/CIDR.h"
#include "ip_parser/parser/IPNet.h"
#include "ip_parser/parser/equal.h"
#include "ip_parser/parser/parseCIDR.h"
#include "ip_parser/parser/dtoi.h"
#include "ip_parser/parser/CIDRMask.h"
#include "ip_parser/parser/Print.h"
#include "ip_parser/parser/byte.h"
#include "ip_parser/parser/parseIPv4.h"
#include "ip_parser/parser/allFF.h"
#include "ip_parser/parser/IPv4.h"
#include "ip_parser/parser/IP.h"
#include "ip_parser/parser/parseIPv6.h"
#include "ip_parser/parser/IPMask.h"
#include "ip_parser/parser/parseIP.h"
#include "ip_parser/parser/xtoi.h"

// exception
#include "exception/casbin_enforcer_exception.h"
#include "exception/exception.h"
#include "exception/missing_required_sections.h"
#include "exception/illegal_argument_exception.h"
#include "exception/io_exception.h"
#include "exception/casbin_adapter_exception.h"
#include "exception/unsupported_operation_exception.h"
#include "exception/casbin_rbac_exception.h"

// config
#include "config/config_interface.h"
#include "config/config.h"

// model
#include "model/function.h"
#include "model/model.h"
#include "model/evaluator.h"
#include "model/assertion.h"

// util
#include "util/ticker.h"
#include "util/built_in_functions.h"
#include "util/util.h"

// error
#include "error/error.h"

// exprtk
#include "exprtk/exprtk.hpp"

// rbac
#include "rbac/role_manager.h"
#include "rbac/rbac.h"
#include "rbac/default_role_manager.h"

// log
#include "log/log_util.h"
#include "log/Logger.h"
#include "log/default_logger.h"

#endif //CASBIN_CPP_CASBIN_H
