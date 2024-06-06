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
#include <map>

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

bool
PluginState::verify_sig(Rule const &rule) const
{
  bool ret = false;
  if (rule.is_signed()) {
    std::shared_ptr<std::vector<PublicKey>> const keys = std::atomic_load(&(this->keys));

    if (keys && !keys->empty()) {
      for (PublicKey const &key : *keys) {
        ret = key.verify(rule.line_without_signature(), rule.signature);
        if (ret) {
          break;
        }
      }
    }
  } else {
    DEBUG_LOG("Rule is not signed");
  }
  return ret;
}

std::shared_ptr<std::vector<Rule>>
PluginState::load_rules(time_t const timenow) const
{
  std::shared_ptr<std::vector<Rule>> rules = std::make_shared<std::vector<Rule>>();

  FILE *const fs = fopen(this->rule_path.c_str(), "r");
  if (nullptr == fs) {
    DEBUG_LOG("Could not open %s for reading", this->rule_path.c_str());
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
        // check rule signature
        if (this->use_signing() && !this->verify_sig(rnew)) {
          DEBUG_LOG("Invalid signature for rule '%s' from line: '%d'", line, lineno);
          continue;
        }

        loaded[rnew.regex_text] = std::move(rnew);
      } else {
        DEBUG_LOG("Invalid rule '%s' from line: '%d'", line, lineno);
      }
    }
  }

  fclose(fs);

  if (loaded.empty()) {
    DEBUG_LOG("No rules loaded from file '%s'", this->rule_path.c_str());
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

std::shared_ptr<std::vector<PublicKey>>
PluginState::load_keys() const
{
  std::shared_ptr<std::vector<PublicKey>> keys = std::make_shared<std::vector<PublicKey>>();

  FILE *const fp = fopen(this->key_path.c_str(), "r");
  if (nullptr == fp) {
    DEBUG_LOG("Could not open key file '%s' for reading", this->key_path.c_str());
    return keys;
  }

  // Load all public keys from file.
  PublicKey pubkey;
  while (pubkey.load(fp)) {
    keys->push_back(std::move(pubkey));
  }

  fclose(fp);

  DEBUG_LOG("Loaded %zu keys from file '%s'", keys->size(), this->key_path.c_str());
  return keys;
}
