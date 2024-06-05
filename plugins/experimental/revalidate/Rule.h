/** @file

  Revalidate rule utilities.

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

#include "tsutil/Regex.h"

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

struct Rule {
  std::string line{}; // original line, for propagation

  std::string regex_text{};
  time_t      expiry{0};
  std::string signature{};

  Regex   regex{};    // compiled regex
  time_t  epoch{0};   // time of rule load
  int64_t version{0}; // typically timestamp

  // loadable string
  static Rule from_string(std::string_view const str, time_t const epoch);

  // header string, percent decode the regex
  static Rule from_header_string(std::string_view const str, time_t const epoch);

  Rule()                      = default;
  Rule(Rule &&orig)           = default;
  Rule &operator=(Rule &&rhs) = default;
  ~Rule()                     = default;

  Rule(Rule const &orig);
  Rule &operator=(Rule const &rhs);
  bool  operator<(Rule const &rhs) const;
  bool  is_valid() const;
  bool  matches(char const *const url, int const url_len) const;
  bool  expired(time_t const timenow) const;

  // loadable string
  std::string to_string() const;

  // informational string (debug)
  std::string info_string() const;

  // header string, percent encode just the regex
  std::string to_header_string() const;
};

// Load rules from a file rules sorted by regex
// Will always return a valid (but maybe empty) vector.
std::shared_ptr<std::vector<Rule>> load_rules_from(std::filesystem::path const &path, time_t const timenow);

// incoming rule must be valid, although can be expired
// "newrule" will be modified to match an already existing rule if not expired.
std::shared_ptr<std::vector<Rule>> merge_new_rule(std::shared_ptr<std::vector<Rule>> const &rules, Rule *const newrule);
