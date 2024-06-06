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

#pragma once

#include "ts/ts.h"

#include "revalidate.h"
#include "Rule.h"
#include "PublicKey.h"

#include <atomic>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

struct PluginState {
  static constexpr std::string_view DefaultPassHeader = {"X-Revalidate-Rule"};

  // header used to for passing rule to parent.
  std::string pass_header{DefaultPassHeader};

  std::filesystem::path rule_path{};
  std::filesystem::path key_path{};

  time_t rule_path_time{0}; // simple check for rule file change
  time_t key_path_time{0};  // simple check for key file change

  // Minimum expiry time for active rules.
  // This is used to optimize the rule matching.
  time_t min_expiry{0};

  // latest rule version.
  // this version is updated by propagated rules.
  // and then reset to latest rule version on rule file change.
  std::atomic<int64_t> version{0};

  // rules sorted by regex_text
  std::shared_ptr<std::vector<Rule>> rules{std::make_shared<std::vector<Rule>>()};

  // active public keys for signature verification
  std::shared_ptr<std::vector<PublicKey>> keys{std::make_shared<std::vector<PublicKey>>()};

  TSTextLogObject log{nullptr};

  PluginState() = default;

  PluginState(PluginState const &)            = delete;
  PluginState(PluginState &&)                 = delete;
  PluginState &operator=(PluginState const &) = delete;
  PluginState &operator=(PluginState &&)      = delete;

  ~PluginState();

  bool from_args(int argc, char const **argv);

  void log_config(std::shared_ptr<std::vector<Rule>> const &newrules) const;

  // if key path specified then rule signing is in play.
  bool use_signing() const;

  // verify rule against public keys.
  bool verify_sig(Rule const &rule) const;

  // load rules from file.
  std::shared_ptr<std::vector<Rule>> load_rules(time_t const timenow) const;

  // load keys from file.
  std::shared_ptr<std::vector<PublicKey>> load_keys() const;
};
