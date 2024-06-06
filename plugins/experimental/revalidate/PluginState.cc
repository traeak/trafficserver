/** @file

  Revalidate plugin state.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include "PluginState.h"

#include <getopt.h>

PluginState::~PluginState()
{
  if (nullptr != log) {
    TSTextLogObjectDestroy(log);
    log = nullptr;
  }
}

void
PluginState::log_config(std::shared_ptr<std::vector<Rule>> const &newrules) const
{
  if (dbg_ctl.on() || nullptr != this->log) {
    DEBUG_LOG("Current config: %s", this->rule_path.c_str());
    if (nullptr != this->log) {
      TSTextLogObjectWrite(log, "Current config: %s", this->rule_path.c_str());
    }

    if (rules && !rules->empty()) {
      for (Rule const &rule : *newrules) {
        std::string const info = rule.info_string();
        DEBUG_LOG("%s", info.c_str());
        if (nullptr != this->log) {
          TSTextLogObjectWrite(this->log, info.c_str());
        }
      }
    } else {
      DEBUG_LOG("Configuration EMPTY");
      if (nullptr != this->log) {
        TSTextLogObjectWrite(this->log, "EMPTY");
      }
    }
  }
}

bool
PluginState::from_args(int argc, char const **argv)
{
  constexpr struct option const longopts[] = {
    {"header",    required_argument, nullptr, 'h'},
    {"key-path",  required_argument, nullptr, 'k'},
    {"log-path",  required_argument, nullptr, 'l'},
    {"rule-path", required_argument, nullptr, 'r'},
    {nullptr,     0,                 nullptr, 0  },
  };

  while (true) {
    int const ch = getopt_long(argc, (char *const *)argv, "h:k:l:r:", longopts, nullptr);
    if (-1 == ch) {
      break;
    }

    switch (ch) {
    case 'h':
      pass_header = optarg;
      DEBUG_LOG("Pass Header: %s", pass_header.c_str());
      break;
    case 'k':
      key_path = optarg;
      if (key_path.is_relative()) {
        key_path = std::filesystem::path(TSConfigDirGet()) / key_path;
      }
      DEBUG_LOG("Key Path: %s", key_path.c_str());
      break;
    case 'l':
      if (TS_SUCCESS == TSTextLogObjectCreate(optarg, TS_LOG_MODE_ADD_TIMESTAMP, &log)) {
        DEBUG_LOG("Logging Mode enabled");
      } else {
        DEBUG_LOG("Unable to set up log");
      }
      break;
    case 'r':
      rule_path = optarg;
      if (rule_path.is_relative()) {
        rule_path = std::filesystem::path(TSConfigDirGet()) / rule_path;
      }
      DEBUG_LOG("Rule Path: %s", rule_path.c_str());
      break;
    default:
      break;
    }
  }

  if (rule_path.empty()) {
    ERROR_LOG("Plugin requires a --rule-path=<path name> option");
    return false;
  }

  if (key_path.empty()) {
    DEBUG_LOG("No key path specified, rule signing not enabled");
  }

  return true;
}

bool
PluginState::use_signing() const
{
  return !key_path.empty();
}
