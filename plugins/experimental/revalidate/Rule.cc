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

#include "Rule.h"

#include "revalidate.h"

#include <array>
#include <charconv>
#include <map>
#include <string>

namespace
{

constexpr int FIELD_REG = 0; // regular expression
constexpr int FIELD_EXP = 1; // rule expiration
constexpr int FIELD_VER = 2; // rule version (typically creation time)
constexpr int FIELD_SIG = 3; // rule version (typically creation time)

template <std::size_t Dim>
std::size_t
split(std::string_view str, std::array<std::string_view, Dim> *const fields)
{
  std::size_t aind = 0;

  using view           = std::string_view;
  constexpr char delim = ' ';

  while (!str.empty()) {
    view::size_type const beg = str.find_first_not_of(delim);
    if (view::npos == beg) {
      break;
    }

    str                       = str.substr(beg);
    view::size_type const end = str.find_first_of(delim);
    (*fields)[aind++]         = str.substr(0, end);
    if (fields->size() <= aind) {
      break;
    }
    str = str.substr(end + 1);
  }

  return aind;
}

} // namespace

// static function
Rule
Rule::from_string(std::string_view const str, time_t const timenow)
{
  Rule rule;

  DEBUG_LOG("Parsing string: '%.*s'", (int)str.size(), str.data());

  std::array<std::string_view, 4> fields;
  std::size_t const               nfields = split(str, &fields);
  if (nfields < 3) {
    DEBUG_LOG("Unable to split '%.*s'", (int)str.size(), str.data());
    return rule;
  }

  rule.regex_text = std::string{fields[FIELD_REG]};
  std::string errstr;
  int         erroff = 0;
  if (!rule.regex.compile(rule.regex_text, errstr, erroff)) {
    DEBUG_LOG("Unable to compile regex: '%s', err: %s, off: %d", rule.regex_text.c_str(), errstr.c_str(), erroff);
    rule.regex_text.clear(); // signals bad regex
    return rule;
  }

  std::string_view const ev{fields[FIELD_EXP]};
  std::from_chars(ev.data(), ev.data() + ev.length(), rule.expiry);
  if (rule.expiry <= 0) {
    DEBUG_LOG("Unable to parse time from: '%.*s'", (int)ev.length(), ev.data());
    return rule;
  }

  std::string_view const sver{fields[FIELD_VER]};
  int64_t                version = 0;
  std::from_chars(sver.data(), sver.data() + sver.length(), version);
  if (version <= 0) {
    DEBUG_LOG("Unable to parse version from: '%.*s'", (int)sver.size(), sver.data());
    return rule;
  } else {
    rule.version = version;
  }

  std::string_view const ssig{fields[FIELD_SIG]};
  if (!ssig.empty()) {
    rule.signature = std::string{ssig};
  }

  rule.line  = std::string{str};
  rule.epoch = timenow;

  return rule;
}

// static function
Rule
Rule::from_header_string(std::string_view const str, time_t const timenow)
{
  Rule rule;

  // just percent decode the whole string
  std::string decoded;
  decoded.resize(str.size());
  size_t len = 0;

  if (TS_SUCCESS != TSStringPercentDecode(str.data(), str.size(), decoded.data(), decoded.size(), &len)) {
    DEBUG_LOG("Unable to percent decode string: '%.*s'", (int)str.size(), str.data());
  } else {
    decoded.resize(len);
    rule = Rule::from_string(decoded, timenow);
  }

  return rule;
}

Rule::Rule(Rule const &orig)
  : line(orig.line),
    regex_text(orig.regex_text),
    expiry(orig.expiry),
    signature(orig.signature),
    epoch(orig.epoch),
    version(orig.version)
{
  std::string error;
  int         erroff = 0;
  if (!this->regex.compile(regex_text, error, erroff)) {
    DEBUG_LOG("Unable to compile regex: '%s', err: %s, off: %d", regex_text.c_str(), error.c_str(), erroff);
    this->regex_text.clear(); // signals bad regex
  }
}

Rule &
Rule::operator=(Rule const &rhs)
{
  if (&rhs != this) {
    this->~Rule();
    new (this) Rule(rhs);
  }
  return *this;
}

bool
Rule::operator<(Rule const &rhs) const
{
  return this->regex_text < rhs.regex_text;
}

bool
Rule::is_valid() const
{
  return !this->line.empty() && !this->regex_text.empty() && 0 < this->expiry && 0 < this->epoch && 0 < this->version;
}

bool
Rule::is_signed() const
{
  return is_valid() && !this->signature.empty();
}

bool
Rule::matches(std::string_view const url) const
{
  if (is_valid()) {
    return this->regex.exec(url);
  }
  return false;
}

bool
Rule::expired(time_t const timenow) const
{
  return this->expiry < timenow;
}

std::string
Rule::info_string() const
{
  std::string res;

  // specified fields
  res.append("regex: ");
  res.append(this->regex_text);
  res.append(" expiry: ");
  res.append(std::to_string(this->expiry));
  res.append(" version: ");
  res.append(std::to_string(this->version));

  // computed fields
  res.append(" epoch: ");
  res.append(std::to_string(this->epoch));

  return res;
}

std::string
Rule::to_string() const
{
  std::string res;

  res.append(this->regex_text);
  res.push_back(' ');
  res.append(std::to_string(this->expiry));
  res.push_back(' ');
  res.append(std::to_string(this->version));

  return res;
}

std::string
Rule::to_header_string() const
{
  std::string res;

  std::string regperc;
  regperc.resize(this->regex_text.length() * 3); // worst case
  size_t len = 0;

  if (TS_SUCCESS != TSStringPercentEncode(this->regex_text.data(), (int)this->regex_text.length(), regperc.data(), regperc.size(),
                                          &len, nullptr)) {
    DEBUG_LOG("Unable to percent encode regex: '%s'", this->regex_text.c_str());
    return res;
  }
  regperc.resize(len);

  res.append(regperc);
  res.push_back(' ');
  res.append(std::to_string(this->expiry));
  res.push_back(' ');
  res.append(std::to_string(this->version));

  return res;
}

std::string_view
Rule::line_without_signature() const
{
  std::string_view res{this->line};
  if (is_signed()) {
    res.remove_suffix(this->signature.size() + 1);
    while (!res.empty() && ' ' == res.back()) {
      res.remove_suffix(1);
    }
  }
  return res;
}

std::shared_ptr<std::vector<Rule>>
load_rules_from(std::filesystem::path const &path, time_t const timenow)
{
  std::shared_ptr<std::vector<Rule>> rules = std::make_shared<std::vector<Rule>>();

  FILE *const fs = fopen(path.c_str(), "r");
  if (nullptr == fs) {
    DEBUG_LOG("Could not open %s for reading", path.c_str());
    return rules;
  }

  // load from file, last one wins
  std::map<std::string, Rule> loaded;
  int                         lineno = 0;
  char                        line[LINE_MAX];
  while (nullptr != fgets(line, LINE_MAX, fs)) {
    ++lineno;
    line[strcspn(line, "\r\n")] = '\0';
    if (0 < strlen(line) && '#' != line[0]) {
      Rule rnew = Rule::from_string(line, timenow);
      if (rnew.is_valid()) {
        loaded[rnew.regex_text] = std::move(rnew);
      } else {
        DEBUG_LOG("Invalid rule '%s' from line: '%d'", line, lineno);
      }
    }
  }

  fclose(fs);

  if (loaded.empty()) {
    DEBUG_LOG("No rules loaded from file '%s'", path.c_str());
    return rules;
  }

  rules->reserve(loaded.size());
  for (auto &elem : loaded) {
    Rule &rule = elem.second;
    if (!rule.expired(timenow)) {
      rules->push_back(std::move(elem.second));
    } else {
      if (dbg_ctl.on()) {
        std::string const str = rule.info_string();
        DEBUG_LOG("Not adding expired rule: '%s'", str.c_str());
      }
    }
  }

  return rules;
}

std::shared_ptr<std::vector<Rule>>
merge_new_rule(std::shared_ptr<std::vector<Rule>> const &rules, Rule *const newrule)
{
  std::shared_ptr<std::vector<Rule>> newrules;

  time_t const timenow = newrule->epoch;

  TSAssert(nullptr != newrule);

  DEBUG_LOG("Existing rules");
  for (auto const &rule : *rules) {
    DEBUG_LOG("  '%s'", rule.regex_text.c_str());
  }

  if (rules->empty()) {
    if (!newrule->expired(timenow)) {
      newrules = std::make_shared<std::vector<Rule>>();
      newrules->push_back(*newrule);
    }
  } else {
    auto itold = std::lower_bound(rules->begin(), rules->end(), *newrule);

    if (rules->end() == itold) { // append
      if (!newrule->expired(timenow)) {
        DEBUG_LOG("Appending as last: '%s'", newrule->regex_text.c_str());
        newrules = std::make_shared<std::vector<Rule>>(*rules);
        newrules->push_back(*newrule);
      }
    } else {
      DEBUG_LOG("Inserting: '%s' lower: '%s'", newrule->regex_text.c_str(), itold->regex_text.c_str());
      // adjust rule expiry or erase it
      if (itold->regex_text == newrule->regex_text) {
        // version check to avoid adding stale rule
        if (itold->version < newrule->version) {
          size_t const index = std::distance(rules->begin(), itold);
          if (newrule->expiry != itold->expiry) {
            newrules = std::make_shared<std::vector<Rule>>(*rules);
            if (!newrule->expired(timenow)) {
              (*newrules)[index].expiry = newrule->expiry;
              (*newrules)[index].epoch  = newrule->epoch;
            } else {
              newrules->erase(newrules->begin() + index);
            }
          } else { // optimization: update new rule epoch in place
            newrule->epoch = (*rules)[index].epoch;
          }
        }
      } else {
        if (!newrule->expired(timenow)) {
          ++itold; // change to std::upper_bound
          newrules = std::make_shared<std::vector<Rule>>(rules->begin(), itold);
          newrules->push_back(*newrule);
          newrules->insert(newrules->end(), itold, rules->end());
        }
      }
    }
  }

  if (nullptr == newrules) {
    DEBUG_LOG("New rules are empty");
  } else {
    DEBUG_LOG("Merged rules");
    for (auto const &rule : *newrules) {
      DEBUG_LOG("  '%s'", rule.regex_text.c_str());
    }
  }

  return newrules;
}
