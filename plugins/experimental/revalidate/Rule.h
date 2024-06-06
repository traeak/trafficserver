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
  // load from a space separated string
  static Rule from_string(std::string_view const str, time_t const epoch);

  // decode regex then load from string
  static Rule from_header_string(std::string_view const str, time_t const epoch);

  std::string line{}; // original line, for propagation

  std::string regex_text{};
  time_t      expiry{0};
  std::string signature{};

  Regex   regex{};    // compiled regex
  time_t  epoch{0};   // time of rule load
  int64_t version{0}; // typically timestamp

  Rule()                      = default;
  Rule(Rule &&orig)           = default;
  Rule &operator=(Rule &&rhs) = default;
  ~Rule()                     = default;

  Rule(Rule const &orig);
  Rule &operator=(Rule const &rhs);

  // compare rules by regex text, for sorting
  bool operator<(Rule const &rhs) const;

  // check if rule is valid in its current state
  bool is_valid() const;

  // check if rule is signed
  bool is_signed() const;

  // perform regex match
  bool matches(std::string_view const url) const;

  // check if rule expired compared to timenow
  bool expired(time_t const timenow) const;

  // loadable string
  std::string to_string() const;

  // informational string (debug)
  std::string info_string() const;

  // header string, percent encode just the regex
  std::string to_header_string() const;

  // line without trailing signature
  std::string_view line_without_signature() const;
};

// Load rules from a file rules sorted by regex
// Will always return a valid (but maybe empty) vector.
std::shared_ptr<std::vector<Rule>> load_rules_from(std::filesystem::path const &path, time_t const timenow);

// incoming rule must be valid, although can be expired
// "newrule" will be modified to match an already existing rule if not expired.
std::shared_ptr<std::vector<Rule>> merge_new_rule(std::shared_ptr<std::vector<Rule>> const &rules, Rule *const newrule);
