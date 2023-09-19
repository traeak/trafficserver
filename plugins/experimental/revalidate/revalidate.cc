/** @file

  ATS plugin to do (simple) regular expression remap rules

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

#include "ts/ts.h"
#include "ts/remap.h"
#include "ts/experimental.h"
#include "regex.h"

#include <array>
#include <atomic>
#include <charconv>
#include <cinttypes>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <getopt.h>
#include <limits.h>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

#define __FILENAME__        (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define DEBUG_LOG(fmt, ...) TSDebug(PLUGIN_NAME, "[%s:% 4d] %s(): " fmt, __FILENAME__, __LINE__, __func__, ##__VA_ARGS__)

#define ERROR_LOG(fmt, ...)                                                                         \
  TSError("[%s/%s:% 4d] %s(): " fmt, PLUGIN_NAME, __FILENAME__, __LINE__, __func__, ##__VA_ARGS__); \
  DEBUG_LOG(fmt, ##__VA_ARGS__)

namespace
{

constexpr char const *const PLUGIN_NAME  = "revalidate";
constexpr char const *const STATE_SUBDIR = "var/trafficserver";
constexpr char const *const PASS_HEADER  = "X-Revalidate-Rule";
constexpr int const OVEC_SIZE            = 30;

// stats management
constexpr char const *const stat_name_count = "plugin.revalidate_count";

static int stat_id_count = TS_ERROR;

void
create_stats()
{
  if (TS_ERROR == stat_id_count && TS_ERROR == TSStatFindName(stat_name_count, &stat_id_count)) {
    stat_id_count = TSStatCreate(stat_name_count, TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);
    if (TS_ERROR != stat_id_count) {
      TSDebug(PLUGIN_NAME, "Created stat '%s'", stat_name_count);
    }
  }
}

static void
increment_stat()
{
  if (TS_ERROR != stat_id_count) {
    TSStatIntIncrement(stat_id_count, 1);
    TSDebug(PLUGIN_NAME, "Incrementing stat '%s'", stat_name_count);
  }
}

struct Rule {
  std::string regex_text{};
  Regex regex{};
  int64_t version{0}; // ms
  time_t epoch{0};
  time_t expiry{0};

  Rule()                      = default;
  Rule(Rule &&orig)           = default;
  Rule &operator=(Rule &&rhs) = default;
  ~Rule()                     = default;

  Rule(Rule const &orig) : regex_text(orig.regex_text), epoch(orig.epoch), expiry(orig.expiry)
  {
    this->regex.compile(regex_text.c_str());
  }

  Rule &
  operator=(Rule const &rhs)
  {
    if (&rhs != this) {
      this->~Rule();
      *this = Rule(rhs);
    }
    return *this;
  }

  // for sorting/finding
  inline bool
  operator<(Rule const &rhs) const
  {
    return this->regex_text < rhs.regex_text;
  }

  inline bool
  is_valid() const
  {
    return !this->regex_text.empty() && this->regex.is_valid() && 0 < version && 0 < expiry && 0 < epoch;
  }

  inline bool
  matches(char const *const url, int const url_len) const
  {
    return this->regex.matches(std::string_view{url, (unsigned)url_len});
  }

  inline bool
  expired(time_t const timenow) const
  {
    return this->expiry < timenow;
  }

  // load from string
  static Rule from_string(std::string_view const str, time_t const epoch);

  // loadable string
  std::string to_string() const;

  // informational string (debug)
  std::string info_string() const;
};

// case insensitive compare
inline bool
iequals(std::string_view const lhs, std::string_view const rhs)
{
  return std::equal(lhs.begin(), lhs.end(), rhs.begin(), rhs.end(),
                    [](char const lch, char const rch) { return tolower(lch) == tolower(rch); });
}

struct PluginState {
  std::filesystem::path rule_path{};
  std::string pass_header{PASS_HEADER};
  time_t rule_path_time{0};
  time_t min_expiry{0};
  int64_t version{0};
  // sorted by regex_text
  std::shared_ptr<std::vector<Rule>> rules{std::make_shared<std::vector<Rule>>()};
  TSTextLogObject log{nullptr};

  PluginState() = default;

  PluginState(PluginState const &)            = delete;
  PluginState(PluginState &&)                 = delete;
  PluginState &operator=(PluginState const &) = delete;
  PluginState &operator=(PluginState &&)      = delete;

  ~PluginState()
  {
    if (nullptr != log) {
      TSTextLogObjectDestroy(log);
      log = nullptr;
    }
  }

  bool from_args(int argc, char const **argv);
  void log_config(std::shared_ptr<std::vector<Rule>> const &newrules) const;
};

template <std::size_t Dim>
std::size_t
split(std::string_view str, std::array<std::string_view, Dim> *const fields)
{
  std::size_t aind = 0;

  using view           = std::string_view;
  constexpr char delim = ' ';

  for (view::size_type ind = 0; ind < str.size(); ++ind) {
    view::size_type const beg = str.find_first_not_of(delim);
    str                       = str.substr(beg);
    if (view::npos != beg) {
      view::size_type const end = str.find_first_of(delim);
      (*fields)[aind++]         = str.substr(0, end);
      if (fields->size() <= aind) {
        break;
      }
      str = str.substr(end + 1);
    }
  }

  return aind;
}

constexpr int FIELD_REG = 0;
constexpr int FIELD_EXP = 1;
constexpr int FIELD_VER = 2;

Rule
Rule::from_string(std::string_view const str, time_t const timenow)
{
  Rule rule;

  DEBUG_LOG("Parsing string: '%.*s'", (int)str.size(), str.data());

  std::array<std::string_view, 3> fields;
  std::size_t const nfields = split(str, &fields);
  if (nfields != fields.size()) {
    DEBUG_LOG("Unable to split '%.*s'", (int)str.size(), str.data());
    return rule;
  }

  rule.regex_text = std::string{fields[FIELD_REG]};
  if (!rule.regex.compile(rule.regex_text.c_str())) {
    DEBUG_LOG("Unable to compile regex: '%s'", rule.regex_text.c_str());
    return rule;
  }

  std::string_view const ev = fields[FIELD_EXP];
  std::from_chars(ev.data(), ev.data() + ev.length(), rule.expiry);
  if (rule.expiry <= 0) {
    DEBUG_LOG("Unable to parse time from: '%.*s'", (int)ev.length(), ev.data());
    return rule;
  }

  std::string_view const sver = fields[FIELD_VER];
  std::from_chars(sver.data(), sver.data() + sver.length(), rule.version);
  if (rule.version <= 0) {
    DEBUG_LOG("Unable to parse version from: '%.*s'", (int)sver.size(), sver.data());
    return rule;
  }

  rule.epoch = timenow;

  return rule;
}

std::string
Rule::info_string() const
{
  std::string res;

  res.append("regex: ");
  res.append(this->regex_text);
  res.append(" epoch: ");
  res.append(std::to_string(this->epoch));
  res.append(" expiry: ");
  res.append(std::to_string(this->expiry));
  res.append(" version: ");
  res.append(std::to_string(this->version));

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

void
PluginState::log_config(std::shared_ptr<std::vector<Rule>> const &newrules) const
{
  TSDebug(PLUGIN_NAME, "Current config: %s", this->rule_path.c_str());
  if (nullptr != this->log) {
    TSTextLogObjectWrite(log, "Current config: %s", this->rule_path.c_str());
  }

  if (rules) {
    for (Rule const &rule : *newrules) {
      std::string const info = rule.info_string();
      TSDebug(PLUGIN_NAME, info.c_str());
      if (nullptr != log) {
        TSTextLogObjectWrite(log, info.c_str());
      }
    }
  } else {
    TSDebug(PLUGIN_NAME, "Configuration EMPTY");
    if (nullptr != this->log) {
      TSTextLogObjectWrite(this->log, "EMPTY");
    }
  }
}

bool
PluginState::from_args(int argc, char const **argv)
{
  constexpr option const longopts[] = {
    {"rule-path", required_argument, nullptr, 'r'},
    {"log-path",  required_argument, nullptr, 'l'},
    {"header",    required_argument, nullptr, 'h'},
    {nullptr,     0,                 nullptr, 0  },
  };

  while (true) {
    int const ch = getopt_long(argc, (char *const *)argv, "h:l:r:s:", longopts, nullptr);
    if (-1 == ch) {
      break;
    }

    switch (ch) {
    case 'h':
      pass_header = optarg;
      DEBUG_LOG("Pass Header: %s", pass_header.c_str());
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

  return true;
}

time_t
time_for_file(std::filesystem::path const &filepath)
{
  time_t mtime{0};
  struct stat fstat;
  if (0 == stat(filepath.c_str(), &fstat)) {
    mtime = fstat.st_mtime;
  } else {
    DEBUG_LOG("Could not stat %s", filepath.c_str());
  }
  return mtime;
}

// Load config, rules sorted by regex_text.
// Will always return a valid (but maybe empty) vector.
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
  int lineno = 0;
  char line[LINE_MAX];
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
      DEBUG_LOG("Not adding expired rule regex: '%s', version: %jd rule: %jd, time: %jd", rule.regex_text.c_str(), rule.version,
                (intmax_t)rule.expiry, (intmax_t)timenow);
    }
  }

  return rules;
}

std::string
percent_encode(std::string_view const to_enc)
{
  std::string res;
  res.resize(to_enc.length() * 3);
  size_t len = 0;
  if (TS_SUCCESS == TSStringPercentEncode(to_enc.data(), (int)to_enc.length(), res.data(), res.size(), &len, nullptr)) {
    res.resize(len);
  } else {
    res.clear();
  }

  return res;
}

std::string
percent_decode(std::string_view const to_dec)
{
  std::string res;
  res.resize(to_dec.length());
  size_t len = 0;
  if (TS_SUCCESS == TSStringPercentDecode(to_dec.data(), to_dec.length(), res.data(), res.size(), &len)) {
    res.resize(len);
  } else {
    res.clear();
  }

  return res;
}

bool
set_rule_header(TSHttpTxn const txnp, std::string_view const header, Rule const &rule)
{
  bool ret = false;

  // percent encode the rule
  std::string const rulestr = rule.to_string();
  DEBUG_LOG("rulestr: %s", rulestr.c_str());
  std::string const encstr = percent_encode(rulestr);
  if (encstr.empty()) {
    DEBUG_LOG("Error percent encoding rule");
    return ret;
  }

  DEBUG_LOG("Encoded rule: %s", encstr.c_str());

  TSMBuffer bufp = nullptr;
  TSMLoc lochdr  = TS_NULL_MLOC;

  if (TS_SUCCESS != TSHttpTxnClientReqGet(txnp, &bufp, &lochdr)) {
    DEBUG_LOG("Unable to get client request from transaction");
    return ret;
  }

  TSMLoc locfield = TSMimeHdrFieldFind(bufp, lochdr, header.data(), header.length());

  if (TS_NULL_MLOC == locfield) {
    // create header
    if (TS_SUCCESS == TSMimeHdrFieldCreateNamed(bufp, lochdr, header.data(), header.length(), &locfield)) {
      if (TS_SUCCESS == TSMimeHdrFieldValueStringSet(bufp, lochdr, locfield, -1, encstr.data(), (int)encstr.length())) {
        TSMimeHdrFieldAppend(bufp, lochdr, locfield);
      }
    }
    TSHandleMLocRelease(bufp, lochdr, locfield);
  } else {
    bool first = true;
    while (locfield) {
      TSMLoc const tmp = TSMimeHdrFieldNextDup(bufp, lochdr, locfield);
      if (first) {
        first = false;
        if (TS_SUCCESS == TSMimeHdrFieldValueStringSet(bufp, lochdr, locfield, -1, encstr.data(), (int)encstr.length())) {
          ret = true;
        }
      } else {
        TSMimeHdrFieldDestroy(bufp, lochdr, locfield);
      }
      TSHandleMLocRelease(bufp, lochdr, locfield);
      locfield = tmp;
    }
  }

  return ret;
}

std::string
get_rule_header(TSHttpTxn const txnp, std::string_view const header)
{
  std::string res;

  TSMBuffer bufp = nullptr;
  TSMLoc lochdr  = TS_NULL_MLOC;

  if (TS_SUCCESS != TSHttpTxnClientReqGet(txnp, &bufp, &lochdr)) {
    DEBUG_LOG("Unable to get client request from transaction");
    return res;
  }

  TSMLoc const locfield = TSMimeHdrFieldFind(bufp, lochdr, header.data(), (int)header.length());
  if (TS_NULL_MLOC != locfield) {
    int len               = 0;
    char const *const str = TSMimeHdrFieldValueStringGet(bufp, lochdr, locfield, -1, &len);

    if (nullptr != str && 0 < len) {
      res.assign(str, len);
    }

    TSHandleMLocRelease(bufp, lochdr, locfield);
  }

  return res;
}

// incoming rule must be valid, although can be expired
// "newrule" will be modified to match an already existing rule if not expired.
std::shared_ptr<std::vector<Rule>>
merge_new_rule(std::shared_ptr<std::vector<Rule>> const &rules, Rule *const newrule)
{
  std::shared_ptr<std::vector<Rule>> newrules;

  time_t const timenow = newrule->epoch;

  TSAssert(nullptr != newrule);

  if (rules->empty()) {
    if (!newrule->expired(timenow)) {
      newrules = std::make_shared<std::vector<Rule>>();
      newrules->push_back(*newrule);
    }
  } else if (*newrule < rules->front()) {
    if (!newrule->expired(timenow)) {
      newrules = std::make_shared<std::vector<Rule>>(1, *newrule);
      newrules->insert(newrules->end(), rules->cbegin(), rules->cend());
    }
  } else {
    auto itold = std::lower_bound(rules->cbegin(), rules->cend(), *newrule);
    TSAssert(rules->cend() != itold);

    // adjust rule expiry or erase it
    // this may cause rule thrashing if the child caches are in
    // rule transition
    if (itold->regex_text == newrule->regex_text) {
      size_t const index = std::distance(rules->cbegin(), itold);
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
    } else {
      if (!newrule->expired(timenow)) {
        ++itold; // change to std::upper_bound
        newrules = std::make_shared<std::vector<Rule>>(rules->cbegin(), itold);
        newrules->push_back(*newrule);
        newrules->insert(newrules->end(), itold, rules->cend());
      }
    }
  }

  return newrules;
}

time_t
get_date_from_cached_hdr(TSHttpTxn txnp)
{
  time_t date = 0;

  TSMBuffer bufp = nullptr;
  TSMLoc lochdr  = TS_NULL_MLOC;

  if (TSHttpTxnCachedRespGet(txnp, &bufp, &lochdr) == TS_SUCCESS) {
    TSMLoc const locdate = TSMimeHdrFieldFind(bufp, lochdr, TS_MIME_FIELD_DATE, TS_MIME_LEN_DATE);
    if (TS_NULL_MLOC != locdate) {
      date = TSMimeHdrFieldValueDateGet(bufp, lochdr, locdate);
      TSHandleMLocRelease(bufp, lochdr, locdate);
    }
  }

  return date;
}

int
main_handler(TSCont cont, TSEvent event, void *edata)
{
  TSHttpTxn txnp            = (TSHttpTxn)edata;
  int status                = TS_ERROR;
  time_t const timenow      = time(nullptr);
  PluginState *const pstate = static_cast<PluginState *>(TSContDataGet(cont));

  std::shared_ptr<std::vector<Rule>> rules;

  // look for incoming rule and merge into current list
  std::string const ruleline = get_rule_header(txnp, pstate->pass_header);
  Rule newrule;
  if (!ruleline.empty()) {
    DEBUG_LOG("Rule from header: %s", ruleline.c_str());
    std::string const decoded = percent_decode(ruleline);
    DEBUG_LOG("Decoded from header: %s", decoded.c_str());
    newrule = Rule::from_string(decoded, timenow);
    if (newrule.is_valid()) { // may be expired
      rules                                       = std::atomic_load(&(pstate->rules));
      std::shared_ptr<std::vector<Rule>> newrules = merge_new_rule(rules, &newrule);

      if (nullptr != newrules) {
        rules = newrules;
        std::atomic_store(&(pstate->rules), newrules);
        pstate->log_config(newrules);
      }
    } else {
      DEBUG_LOG("Error decoding rule");
    }
  }

  DEBUG_LOG("main_handler: %s", TSHttpEventNameLookup(event));

  switch (event) {
  case TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE:
    if (TS_SUCCESS == TSHttpTxnCacheLookupStatusGet(txnp, &status)) {
      DEBUG_LOG("main_handler: cache hit status %d", status);
      switch (status) {
      case TS_CACHE_LOOKUP_HIT_FRESH: {
        time_t cached_date = 0;
        char *url          = nullptr;
        int url_len        = 0;

        bool matched = false;

        // check if passed in decoded rule still applies
        if (newrule.is_valid() && !newrule.expired(timenow)) {
          cached_date = get_date_from_cached_hdr(txnp);
          if (cached_date <= newrule.epoch) {
            DEBUG_LOG("Checking passed in rule: %s", newrule.regex_text.c_str());
            url = TSHttpTxnEffectiveUrlStringGet(txnp, &url_len);

            if (nullptr != url && 0 < url_len) {
              DEBUG_LOG("url to evaluate: '%.*s'", url_len, url);

              if (newrule.matches(url, url_len)) {
                TSHttpTxnCacheLookupStatusSet(txnp, TS_CACHE_LOOKUP_HIT_STALE);
                increment_stat();
                DEBUG_LOG("Forced revalidate - %.*s", url_len, url);
                matched = true;
              }
            } else {
              DEBUG_LOG("Error getting effective url");
            }
          }
        }

        if (!matched) {
          // go through our rule set
          if (nullptr == rules) {
            rules = std::atomic_load(&(pstate->rules));
            TSAssert(nullptr != rules);
          }

          for (Rule const &rule : *rules) {
            if (rule.regex_text == newrule.regex_text || rule.expired(timenow)) {
              continue;
            }

            if (0 == cached_date) {
              cached_date = get_date_from_cached_hdr(txnp);
            }

            if (cached_date <= rule.epoch) {
              DEBUG_LOG("Checking rule: %s", rule.regex_text.c_str());
              if (nullptr == url) {
                url = TSHttpTxnEffectiveUrlStringGet(txnp, &url_len);
                if (nullptr == url || 0 == url_len) {
                  DEBUG_LOG("Error getting effective url");
                  break;
                }
                DEBUG_LOG("url to evaluate: '%.*s'", url_len, url);
              }

              if (rule.matches(url, url_len)) {
                TSHttpTxnCacheLookupStatusSet(txnp, TS_CACHE_LOOKUP_HIT_STALE);
                DEBUG_LOG("Forced revalidate - %.*s", url_len, url);

                // Set/Replace revalidate header
                set_rule_header(txnp, pstate->pass_header, rule);
                break;
              } else {
                DEBUG_LOG("Rule doesn't match: %s", rule.regex_text.c_str());
              }
            }
          }
        }

        if (nullptr != url) {
          TSfree(url);
        }
      } break;
      case TS_CACHE_LOOKUP_MISS:
      case TS_CACHE_LOOKUP_SKIPPED: {
        if (nullptr == rules) {
          rules = std::atomic_load(&(pstate->rules));
          TSAssert(nullptr != rules);
        }

        char *url   = nullptr;
        int url_len = 0;

        // check for matching rule to pass along
        for (Rule const &rule : *rules) {
          if (!rule.expired(timenow)) {
            if (nullptr == url) {
              url = TSHttpTxnEffectiveUrlStringGet(txnp, &url_len);
              if (nullptr == url || 0 == url_len) {
                DEBUG_LOG("Error getting effective url");
                break;
              }
              DEBUG_LOG("url to evaluate: '%.*s'", url_len, url);
            }
            if (rule.matches(url, url_len)) {
              // Set/Replace the rule to a header
              set_rule_header(txnp, pstate->pass_header, rule);
              break;
            }
          }
        }

        if (nullptr != url) {
          TSfree(url);
        }
      } break;
      default:
        break;
      }
    }
    break;
  default:
    break;
  }

  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  return 0;
}

bool
process_rules(PluginState *const pstate)
{
  time_t const timepath = time_for_file(pstate->rule_path);
  if (timepath == pstate->rule_path_time) {
    return false;
  }

  time_t const timenow                        = time(NULL);
  std::shared_ptr<std::vector<Rule>> newrules = load_rules_from(pstate->rule_path, timenow);

  std::shared_ptr<std::vector<Rule>> oldrules = std::atomic_load(&(pstate->rules));

  bool changed = false;

  if (oldrules->empty() && !newrules->empty()) {
    auto itnew = newrules->begin();
    while (newrules->end() != itnew) {
      if (itnew->expired(timenow)) {
        itnew = newrules->erase(itnew);
      } else {
        changed = true;
        ++itnew;
      }
    }
  } else if (!oldrules->empty() && newrules->empty()) { // all rules removed
    changed = true;
  } else if (!oldrules->empty() && !newrules->empty()) {
    auto itold = oldrules->cbegin();
    auto itnew = newrules->begin();

    while (oldrules->cend() != itold && newrules->end() != itnew) {
      // check for any changes
      int const cres = itold->regex_text.compare(itnew->regex_text);
      if (cres < 0) {                   // new item not in old
        if (!itnew->expired(timenow)) { // rule is already expired
          itnew = newrules->erase(itnew);
        } else { // new rule
          changed = true;
          ++itnew;
        }
      } else if (0 == cres) {                 // rule match
        if (itnew->expiry != itold->expiry) { // expiration changed
          changed = true;

          if (itnew->expired(timenow)) {
            itnew = newrules->erase(itnew);
          } else {
            ++itnew;
          }
          ++itold;
        } else { // retain the old epoch
          itnew->epoch = itold->epoch;
          ++itold;
          ++itnew;
        }
      } else if (0 < cres) { // old item not in new
        if (!itold->expired(timenow)) {
          changed = true;
        }
        ++itold;
      }
    }

    // any extra old rules are removed
    if (oldrules->cend() != itold) {
      changed = true;
    }

    // Retain any trailing unexpired new rules
    while (newrules->end() != itnew) {
      if (itnew->expired(timenow)) {
        itnew = newrules->erase(itnew);
      } else {
        changed = true;
        ++itnew;
      }
    }
  }

  if (changed) {
    std::atomic_store(&(pstate->rules), newrules);
    DEBUG_LOG("new rules installed");
  }

  pstate->rule_path_time = timepath;

  return true;
}

int
rule_handler(TSCont cont, TSEvent event, void *data)
{
  if (TS_EVENT_LIFECYCLE_MSG == event) {
    TSPluginMsg const *const msg = static_cast<TSPluginMsg *>(data);
    if (0 != strcmp(PLUGIN_NAME, msg->tag)) {
      return TS_EVENT_NONE;
    }
    DEBUG_LOG("Handling lifecycle message");
  }
  PluginState *const pstate = static_cast<PluginState *>(TSContDataGet(cont));
  DEBUG_LOG("Reloading rules");
  process_rules(pstate);
  return TS_EVENT_NONE;
}

} // namespace

void
TSPluginInit(int argc, char const *argv[])
{
  DEBUG_LOG("Starting plugin init");

  TSPluginRegistrationInfo info;
  info.plugin_name   = PLUGIN_NAME;
  info.vendor_name   = "Apache Software Foundation";
  info.support_email = "dev@trafficserver.apache.org";

  if (TSPluginRegister(&info) != TS_SUCCESS) {
    ERROR_LOG("Global plugin registration failed");
    return;
  } else {
    DEBUG_LOG("Global plugin registration succeeded");
  }

  if (TS_VERSION_MAJOR != TSTrafficServerVersionGetMajor()) {
    ERROR_LOG("Plugin requires Traffic Server %d", TS_VERSION_MAJOR);
    return;
  }

  PluginState *const pstate = new PluginState;
  if (!pstate->from_args(argc, argv)) {
    ERROR_LOG("Remap plugin registration failed");
    delete pstate;
    return;
  }

  create_stats();

  TSCont const main_cont = TSContCreate(main_handler, nullptr);
  TSContDataSet(main_cont, static_cast<void *>(pstate));
  TSHttpHookAdd(TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, main_cont);

  time_t const timenow = time(nullptr);

  // load rules from path
  std::shared_ptr<std::vector<Rule>> newrules = load_rules_from(pstate->rule_path, timenow);

  // Calculate next time a rule expires
  if (nullptr != newrules) {
    std::atomic_store(&(pstate->rules), newrules);
  }

  pstate->log_config(newrules);

  // receive plugin messages
  TSCont const lcont = TSContCreate(rule_handler, TSMutexCreate());
  TSContDataSet(lcont, pstate);
  TSLifecycleHookAdd(TS_LIFECYCLE_MSG_HOOK, lcont);

  // occasionally check for rule reload
  TSCont const rcont = TSContCreate(rule_handler, TSMutexCreate());
  TSContDataSet(rcont, pstate);
  TSMgmtUpdateRegister(rcont, PLUGIN_NAME);

  DEBUG_LOG("Global Plugin Init Complete");
}
