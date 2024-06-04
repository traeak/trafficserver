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
#include "ts/remap_version.h"
#include "tsutil/Regex.h"

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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#define PLUGIN_NAME         "revalidate"
#define DEBUG_LOG(fmt, ...) Dbg(dbg_ctl, "[%s:%d] %s(): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#define ERROR_LOG(fmt, ...)                                                   \
  TSError("[%s:%d] %s(): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
  DEBUG_LOG(fmt, ##__VA_ARGS__)

namespace
{

DbgCtl dbg_ctl{PLUGIN_NAME};

constexpr std::string_view DefaultPassHeader = {"X-Revalidate-Rule"};

// stats management
constexpr char const *const stat_name_count = "plugin.revalidate_count";

int stat_id_count = TS_ERROR;

void
create_stats()
{
  if (TS_ERROR == stat_id_count && TS_ERROR == TSStatFindName(stat_name_count, &stat_id_count)) {
    stat_id_count = TSStatCreate(stat_name_count, TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);
    if (TS_ERROR != stat_id_count) {
      DEBUG_LOG("Created stat '%s'", stat_name_count);
    }
  }
}

void
increment_stat()
{
  if (TS_ERROR != stat_id_count) {
    TSStatIntIncrement(stat_id_count, 1);
    DEBUG_LOG("Incrementing stat '%s'", stat_name_count);
  }
}

struct Rule {
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

  Rule(Rule const &orig)
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
  operator=(Rule const &rhs)
  {
    if (&rhs != this) {
      this->~Rule();
      new (this) Rule(rhs);
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
    return !line.empty() && !regex_text.empty() && 0 < expiry && 0 < epoch && 0 < version;
  }

  inline bool
  matches(char const *const url, int const url_len) const
  {
    if (is_valid()) {
      return this->regex.exec(std::string_view{url, (unsigned)url_len});
    }
    return false;
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

struct PubKey {
  EVP_PKEY *key{nullptr};

  PubKey() = default;
  PubKey(EVP_PKEY *const ikey) { key = ikey; }
  PubKey(PubKey &&)                 = default;
  PubKey(PubKey const &)            = delete;
  PubKey &operator=(PubKey &&)      = default;
  PubKey &operator=(PubKey const &) = delete;
  ~PubKey()
  {
    if (nullptr != key) {
      EVP_PKEY_free(key);
    }
  }

  bool load(FILE *const fp);

  bool
  is_valid() const
  {
    return nullptr != key;
  }
  bool
  verify(std::string_view const data, std::string_view const sig) const
  {
    if (!is_valid()) {
      return false;
    }

    EVP_MD_CTX *const ctx = EVP_MD_CTX_new();
    if (nullptr == ctx) {
      return false;
    }

    bool ret = false;
    if (1 == EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, key)) {
      if (1 == EVP_DigestVerifyUpdate(ctx, data.data(), data.length())) {
        ret = (1 == EVP_DigestVerifyFinal(ctx, (unsigned char const *)sig.data(), sig.length()));
      }
    }

    EVP_MD_CTX_free(ctx);

    return ret;
  }
};

bool
PubKey::load(FILE *const fp)
{
  // unload any existing key
  if (nullptr != key) {
    EVP_PKEY_free(key);
    key = nullptr;
  }

  key = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
  if (nullptr == key && dbg_ctl.on()) {
    BIO *const bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char      *errbuf = nullptr;
    long const errlen = BIO_get_mem_data(bio, &errbuf);
    DEBUG_LOG("Could not read public key from file, errors: %.*s", (int)errlen, errbuf);
    BIO_free(bio);
  }

  return nullptr != key;
}

struct PluginState {
  // header used to for passing rule to parent.
  std::string pass_header{DefaultPassHeader};

  std::filesystem::path rule_path{};
  std::filesystem::path key_path{};

  time_t rule_path_time{0}; // simple check for rule file change
  time_t key_path_time{0};  // simple check for key file change

  // optimization, updated with rule changes
  time_t min_expiry{0};

  // latest rule version.
  // this version is updated by propagated rules.
  // and then reset to latest rule version on rule file change.
  std::atomic<int64_t> version{0};

  // rules sorted by regex_text
  std::shared_ptr<std::vector<Rule>> rules{std::make_shared<std::vector<Rule>>()};

  // active public keys for signature verification
  std::shared_ptr<std::vector<PubKey>> keys{std::make_shared<std::vector<PubKey>>()};

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

constexpr int FIELD_REG = 0; // regular expression
constexpr int FIELD_EXP = 1; // rule expiration
constexpr int FIELD_VER = 2; // rule version (typically creation time)

// Parse rules from string.
// Timenow becomes the epoch for new/changed rules.
Rule
Rule::from_string(std::string_view const str, time_t const timenow)
{
  Rule rule;

  DEBUG_LOG("Parsing string: '%.*s'", (int)str.size(), str.data());

  std::array<std::string_view, 3> fields;
  std::size_t const               nfields = split(str, &fields);
  if (nfields != fields.size()) {
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

  rule.line  = std::string{str};
  rule.epoch = timenow;

  return rule;
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
  constexpr option const longopts[] = {
    {"header",    required_argument, nullptr, 'h'}, // header for passing rule
    {"key-path",  required_argument, nullptr, 'k'}, // path to public keys file
    {"log-path",  required_argument, nullptr, 'l'}, // path to log file
    {"rule-path", required_argument, nullptr, 'r'}, // path to rule file
    {nullptr,     0,                 nullptr, 0  },
  };

  while (true) {
    int const ch = getopt_long(argc, (char *const *)argv, "h:k:l:r:s:", longopts, nullptr);
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
    DEBUG_LOG("Rule key signing not enabled");
  }

  return true;
}

time_t
time_for_file(std::filesystem::path const &filepath)
{
  time_t      mtime{0};
  struct stat fstat;
  if (0 == stat(filepath.c_str(), &fstat)) {
    mtime = fstat.st_mtime;
  } else {
    DEBUG_LOG("Could not stat %s", filepath.c_str());
  }
  return mtime;
}

// Load public keys from path.
std::shared_ptr<std::vector<PubKey>>
load_keys_from(std::filesystem::path const &path)
{
  std::shared_ptr<std::vector<PubKey>> keys = std::make_shared<std::vector<PubKey>>();

  FILE *const fp = fopen(path.c_str(), "r");
  if (nullptr == fp) {
    DEBUG_LOG("Could not open key file '%s' for reading", path.c_str());
    return keys;
  }

  // Load all public keys from file.
  PubKey pubkey;
  while (pubkey.load(fp)) {
    keys->push_back(std::move(pubkey));
  }

  fclose(fp);

  DEBUG_LOG("Loaded %zu keys from file '%s'", keys->size(), path.c_str());
  return keys;
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

  TSMBuffer bufp   = nullptr;
  TSMLoc    lochdr = TS_NULL_MLOC;

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

  TSMBuffer bufp   = nullptr;
  TSMLoc    lochdr = TS_NULL_MLOC;

  if (TS_SUCCESS != TSHttpTxnClientReqGet(txnp, &bufp, &lochdr)) {
    DEBUG_LOG("Unable to get client request from transaction");
    return res;
  }

  TSMLoc const locfield = TSMimeHdrFieldFind(bufp, lochdr, header.data(), (int)header.length());
  if (TS_NULL_MLOC != locfield) {
    int               len = 0;
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

time_t
get_date_from_cached_hdr(TSHttpTxn txnp)
{
  time_t date = 0;

  TSMBuffer bufp   = nullptr;
  TSMLoc    lochdr = TS_NULL_MLOC;

  if (TSHttpTxnCachedRespGet(txnp, &bufp, &lochdr) == TS_SUCCESS) {
    TSMLoc const locdate = TSMimeHdrFieldFind(bufp, lochdr, TS_MIME_FIELD_DATE, TS_MIME_LEN_DATE);
    if (TS_NULL_MLOC != locdate) {
      date = TSMimeHdrFieldValueDateGet(bufp, lochdr, locdate);
      TSHandleMLocRelease(bufp, lochdr, locdate);
    }
  }

  return date;
}

// continuation calls into this
int
cache_lookup_handler(TSCont cont, TSEvent event, void *edata)
{
  TSHttpTxn          txnp    = (TSHttpTxn)edata;
  int                status  = TS_ERROR;
  time_t const       timenow = time(nullptr);
  PluginState *const pstate  = static_cast<PluginState *>(TSContDataGet(cont));

  std::shared_ptr<std::vector<Rule>> rules;

  // look for incoming rule and merge into current list
  std::string const ruleline = get_rule_header(txnp, pstate->pass_header);
  Rule              newrule;
  if (!ruleline.empty()) {
    DEBUG_LOG("Rule from header: %s", ruleline.c_str());
    std::string const decoded = percent_decode(ruleline);
    DEBUG_LOG("Decoded from header: %s", decoded.c_str());
    newrule = Rule::from_string(decoded, timenow);
    if (newrule.is_valid()) { // may be expired

      // check if rule is a newer version
      int64_t const pver = pstate->version;
      if (pver < newrule.version) {
        DEBUG_LOG("version: pstate: %jd, rule: %jd", pver, newrule.version);

        rules = std::atomic_load(&(pstate->rules));

        // this may adjust the "newrule"
        std::shared_ptr<std::vector<Rule>> newrules = merge_new_rule(rules, &newrule);

        if (nullptr != newrules) {
          rules = newrules;
          std::atomic_store(&(pstate->rules), newrules);
          pstate->log_config(newrules);
        }
      } else {
        DEBUG_LOG("Out of date rule skipped and invalidated");
        newrule = Rule{};
      }
    } else {
      DEBUG_LOG("Error decoding rule");
    }
  }

  DEBUG_LOG("event: %s", TSHttpEventNameLookup(event));

  switch (event) {
  case TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE:
    if (TS_SUCCESS == TSHttpTxnCacheLookupStatusGet(txnp, &status)) {
      DEBUG_LOG("cache hit status %d", status);
      switch (status) {
      case TS_CACHE_LOOKUP_HIT_FRESH: {
        time_t cached_date = 0;
        char  *url         = nullptr;
        int    url_len     = 0;

        bool matched = false;

        // check if passed in decoded rule applies
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

        char *url     = nullptr;
        int   url_len = 0;

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
process_keys(PluginState *const pstate)
{
  if (pstate->key_path.empty()) {
    DEBUG_LOG("Rule signing not enabled");
    return true;
  }

  time_t const timepath = time_for_file(pstate->rule_path);
  if (0 == timepath) {
    DEBUG_LOG("Key file '%s' requested, but missing", pstate->key_path.c_str());
    return false;
  }

  // file unchanged
  if (timepath == pstate->key_path_time) {
    DEBUG_LOG("Key file '%s' unchanged", pstate->key_path.c_str());
    return true;
  }

  // load keys from path
  std::shared_ptr<std::vector<PubKey>> newkeys = load_keys_from(pstate->key_path);

  if (newkeys->empty()) {
    DEBUG_LOG("No keys loaded from file '%s'", pstate->key_path.c_str());
    return false;
  }

  std::atomic_store(&(pstate->keys), newkeys);
  pstate->key_path_time = timepath;

  return true;
}

bool
process_rules(PluginState *const pstate)
{
  time_t const timepath = time_for_file(pstate->rule_path);
  if (timepath == pstate->rule_path_time) {
    return false;
  }

  time_t const                       timenow  = time(NULL);
  std::shared_ptr<std::vector<Rule>> newrules = load_rules_from(pstate->rule_path, timenow);

  std::shared_ptr<std::vector<Rule>> oldrules = std::atomic_load(&(pstate->rules));

  bool changed = false;

  // merge epochs from old rules to new rules
  auto itold = oldrules->cbegin();
  auto itnew = newrules->begin();

  // transfer epochs from current rules to new rules
  while (oldrules->cend() != itold && newrules->end() != itnew) {
    int const cres = itold->regex_text.compare(itnew->regex_text);
    if (cres < 0) { // new item not in old
      changed = true;
      ++itold;
    } else if (0 == cres) {                 // items match
      if (itnew->expiry != itold->expiry) { // expiration change
        changed = true;
      } else { // same rule, transfer epoch
        itnew->epoch = itold->epoch;
      }
      ++itold;
      ++itnew;
    } else { // if (0 < cres) // old item not in new
      changed = true;
      ++itnew;
    }
  }

  // any extra rules?
  if (oldrules->cend() != itold || newrules->end() != itnew) {
    changed = true;
  }

  if (changed) {
    // remove intentionally expired rules
    // Compute new version based on current ruleset.
    // New propagated rules may update that version.
    int64_t newver = 0;

    itnew = newrules->begin();
    while (newrules->end() != itnew) {
      newver = std::max(newver, itnew->version);
      if (itnew->expired(timenow)) {
        itnew = newrules->erase(itnew);
      } else {
        ++itnew;
      }
    }

    pstate->version = newver;

    DEBUG_LOG("Changes detected, new rules installed");
    pstate->log_config(newrules);

    /*
        // at this point all rules should share the same version (that's a lie?)
        if (!newrules->empty()) {
          pstate->version = newrules->front().version;
        }
    */

    std::atomic_store(&(pstate->rules), newrules);
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
  DEBUG_LOG("Reloading keys");
  process_keys(pstate);
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

  TSCont const main_cont = TSContCreate(cache_lookup_handler, nullptr);
  TSContDataSet(main_cont, static_cast<void *>(pstate));
  TSHttpHookAdd(TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, main_cont);

  time_t const timenow = time(nullptr);

  // load keys from path
  std::shared_ptr<std::vector<PubKey>> newkeys;
  if (!pstate->key_path.empty()) {
    pstate->key_path_time = time_for_file(pstate->key_path);
    newkeys               = load_keys_from(pstate->rule_path);
    if (newkeys->empty()) {
      DEBUG_LOG("No keys loaded from file '%s', all rules will be rejected!", pstate->key_path.c_str());
    } else {
      std::atomic_store(&(pstate->keys), newkeys);
    }
  }

  // load rules from path -- sig check should be done here during load!!!
  std::shared_ptr<std::vector<Rule>> newrules = load_rules_from(pstate->rule_path, timenow);

  // set new rules
  if (nullptr != newrules) {
    int64_t newver = 0;

    // scan for latest version and also trim out expired rules
    auto itnew = newrules->begin();
    while (newrules->end() != itnew) {
      newver = std::max(newver, itnew->version);
      if (itnew->expired(timenow)) {
        itnew = newrules->erase(itnew);
      } else {
        ++itnew;
      }
    }

    pstate->version = newver;

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
