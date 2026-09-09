/*
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

//////////////////////////////////////////////////////////////////////////////
// A web application firewall for ATS, backed by libmodsecurity (ModSecurity
// v3).
//
// It works both as a global plugin, taking the ModSecurity rule files as
// arguments in plugin.config:
//
//   waf.so waf/example.conf
//
// and as a remap plugin, taking them as pparams:
//
//   map http://example.com/ http://origin/ @plugin=waf.so @pparam=waf/example.conf
//
//////////////////////////////////////////////////////////////////////////////

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <modsecurity/intervention.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>

#include <ts/ts.h>
#include <ts/remap.h>
#include <ts/remap_version.h>

namespace
{
constexpr char PLUGIN_NAME[]    = "waf";
constexpr char PLUGIN_VENDOR[]  = "Apache Software Foundation";
constexpr char PLUGIN_SUPPORT[] = "dev@trafficserver.apache.org";

// Payload of "traffic_ctl plugin msg waf <cmd>" that reloads the rule files.
constexpr std::string_view RELOAD_CMD = "reload";

constexpr std::string_view ERROR_BODY  = "Blocked by ModSecurity\n";
constexpr std::string_view ERROR_CTYPE = "text/plain";

DbgCtl dbg_ctl{PLUGIN_NAME};

///////////////////////////////////////////////////////////////////////////////
// Owner of a ModSecurity rule set. Rule sets are shared by every transaction
// that started while they were current, so they are handed out as shared_ptr
// and only torn down once the last transaction using them has finished.
//
class RuleSet
{
public:
  RuleSet() : _rules(modsecurity::msc_create_rules_set()) {}

  ~RuleSet()
  {
    if (_rules != nullptr) {
      modsecurity::msc_rules_cleanup(_rules);
    }
  }

  RuleSet(RuleSet const &)            = delete;
  RuleSet &operator=(RuleSet const &) = delete;

  bool
  add_file(std::string const &path)
  {
    if (_rules == nullptr) {
      return false;
    }

    char const *error = nullptr;

    if (modsecurity::msc_rules_add_file(_rules, path.c_str(), &error) < 0) {
      TSError("[%s] failed to load rules from %s: %s", PLUGIN_NAME, path.c_str(), error != nullptr ? error : "unknown error");
      modsecurity::msc_rules_error_cleanup(error);
      return false;
    }

    Dbg(dbg_ctl, "loaded rules from %s", path.c_str());
    return true;
  }

  modsecurity::RulesSet *
  get() const
  {
    return _rules;
  }

private:
  modsecurity::RulesSet *_rules = nullptr;
};

///////////////////////////////////////////////////////////////////////////////
// The ModSecurity instance. Shared by the global plugin and every remap
// instance, whichever of them initializes first.
//
modsecurity::ModSecurity *g_modsec = nullptr;
std::once_flag            g_modsec_once;

// ModSecurity hands us the messages produced by rules with a "log" action.
void
modsec_log(void * /* data */, void const *message)
{
  if (message != nullptr) {
    TSNote("[%s] %s", PLUGIN_NAME, static_cast<char const *>(message));
  }
}

bool
init_modsecurity()
{
  std::call_once(g_modsec_once, []() {
    g_modsec = modsecurity::msc_init();
    if (g_modsec == nullptr) {
      TSError("[%s] failed to initialize ModSecurity", PLUGIN_NAME);
      return;
    }

    std::string const connector = std::string("ModSecurity-ats ") + TSTrafficServerVersionGet();

    modsecurity::msc_set_connector_info(g_modsec, connector.c_str());
    modsecurity::msc_set_log_cb(g_modsec, modsec_log);
  });

  return g_modsec != nullptr;
}

///////////////////////////////////////////////////////////////////////////////
// The rule files of one plugin instance, along with the rule set currently
// loaded from them. The global instance can be reloaded at runtime; remap
// instances are simply recreated when remap.config is reloaded.
//
class RuleConfig
{
public:
  // Rule file paths, relative ones resolved against the configuration
  // directory. Returns false if the rules could not be loaded.
  bool
  init(std::vector<std::string> const &files)
  {
    std::string const config_dir(TSConfigDirGet());

    for (auto const &file : files) {
      _files.emplace_back(!file.empty() && file[0] == '/' ? file : config_dir + "/" + file);
    }

    return reload();
  }

  // Load every rule file into a fresh rule set and make it current. The
  // previously loaded rules are kept if any file fails to parse, so that a bad
  // edit never leaves the plugin without rules.
  bool
  reload()
  {
    auto rules = std::make_shared<RuleSet>();

    if (rules->get() == nullptr) {
      TSError("[%s] failed to create a ModSecurity rule set", PLUGIN_NAME);
      return false;
    }

    for (auto const &file : _files) {
      if (!rules->add_file(file)) {
        return false;
      }
    }

    std::unique_lock lock(_mutex);

    _rules = std::move(rules);
    return true;
  }

  std::shared_ptr<RuleSet>
  rules() const
  {
    std::shared_lock lock(_mutex);

    return _rules;
  }

private:
  std::vector<std::string>  _files;
  std::shared_ptr<RuleSet>  _rules;
  mutable std::shared_mutex _mutex;
};

// The global plugin instance, null when the plugin is only used for remap.
RuleConfig *g_config = nullptr;

///////////////////////////////////////////////////////////////////////////////
// Per transaction state. Owned by the transaction's continuation and released
// on TS_HTTP_TXN_CLOSE_HOOK.
//
struct TxnContext {
  modsecurity::Transaction *msc_txn = nullptr;
  std::shared_ptr<RuleSet>  rules; // keeps the rules alive for this transaction
  std::string               redirect_url;
  int                       status = 0; // status to force on the client response

  ~TxnContext()
  {
    if (msc_txn != nullptr) {
      modsecurity::msc_process_logging(msc_txn);
      modsecurity::msc_transaction_cleanup(msc_txn);
    }
  }
};

// What ModSecurity wants us to do, extracted from a ModSecurityIntervention.
struct Intervention {
  bool        disrupt = false;
  int         status  = 200;
  std::string url;
};

///////////////////////////////////////////////////////////////////////////////
// Small helpers.
//
void
address_to_string(sockaddr const *addr, char (&buf)[INET6_ADDRSTRLEN], int &port)
{
  buf[0] = '\0';
  port   = 0;

  if (addr == nullptr) {
    return;
  }

  switch (addr->sa_family) {
  case AF_INET: {
    auto const *in = reinterpret_cast<sockaddr_in const *>(addr);

    inet_ntop(AF_INET, &in->sin_addr, buf, sizeof(buf));
    port = ntohs(in->sin_port);
  } break;
  case AF_INET6: {
    auto const *in6 = reinterpret_cast<sockaddr_in6 const *>(addr);

    inet_ntop(AF_INET6, &in6->sin6_addr, buf, sizeof(buf));
    port = ntohs(in6->sin6_port);
  } break;
  default:
    break;
  }
}

void
add_headers(TSMBuffer bufp, TSMLoc hdr_loc, modsecurity::Transaction *msc_txn, bool request)
{
  int const count = TSMimeHdrFieldsCount(bufp, hdr_loc);

  for (int i = 0; i < count; ++i) {
    TSMLoc field = TSMimeHdrFieldGet(bufp, hdr_loc, i);

    if (field == TS_NULL_MLOC) {
      continue;
    }

    int         name_len  = 0;
    int         value_len = 0;
    char const *name      = TSMimeHdrFieldNameGet(bufp, hdr_loc, field, &name_len);
    char const *value     = TSMimeHdrFieldValueStringGet(bufp, hdr_loc, field, -1, &value_len);

    if (name != nullptr && value != nullptr) {
      auto const *key = reinterpret_cast<unsigned char const *>(name);
      auto const *val = reinterpret_cast<unsigned char const *>(value);

      if (request) {
        modsecurity::msc_add_n_request_header(msc_txn, key, name_len, val, value_len);
      } else {
        modsecurity::msc_add_n_response_header(msc_txn, key, name_len, val, value_len);
      }
    }

    TSHandleMLocRelease(bufp, hdr_loc, field);
  }
}

std::string
http_version(TSMBuffer bufp, TSMLoc hdr_loc)
{
  int const version = TSHttpHdrVersionGet(bufp, hdr_loc);

  return std::to_string(TS_HTTP_MAJOR(version)) + "." + std::to_string(TS_HTTP_MINOR(version));
}

// Ask ModSecurity whether the rules that just ran want us to interfere.
Intervention
check_intervention(modsecurity::Transaction *msc_txn)
{
  modsecurity::ModSecurityIntervention iv;
  Intervention                         result;

  modsecurity::intervention::clean(&iv);

  if (modsecurity::msc_intervention(msc_txn, &iv) == 0) {
    return result;
  }

  if (iv.log != nullptr) {
    TSNote("[%s] %s", PLUGIN_NAME, iv.log);
  }

  // A redirect target may embed macro expansions of decoded request data, so it
  // can carry bytes that are not legal in a header value. Drop the redirect
  // whole rather than truncating it, which would leave a partially attacker
  // controlled target. The transaction is still disrupted by the status.
  if (iv.url != nullptr) {
    std::string_view const url(iv.url);

    if (std::none_of(url.begin(), url.end(), [](unsigned char c) { return c < 0x20 || c == 0x7f; })) {
      result.url = url;
    } else {
      TSWarning("[%s] dropping an intervention redirect containing control characters", PLUGIN_NAME);
    }
  }

  result.status  = iv.status;
  result.disrupt = iv.status != 200 || !result.url.empty();

  Dbg(dbg_ctl, "intervention with status %d%s", iv.status, result.url.empty() ? "" : " and a redirect");
  modsecurity::msc_intervention_cleanup(&iv);

  return result;
}

// Record what the intervention asks for and arrange for the client response to
// be built from it. The status and the Location header are put in place at
// TS_HTTP_SEND_RESPONSE_HDR_HOOK, because the internal response that ATS builds
// for an aborted transaction is a 500 unless the status is 4xx or 5xx.
void
apply_intervention(TSHttpTxn txnp, TSCont contp, TxnContext *ctx, Intervention const &iv)
{
  ctx->redirect_url = iv.url;

  if (iv.status != 200) {
    ctx->status = iv.status;
    TSHttpTxnStatusSet(txnp, static_cast<TSHttpStatus>(iv.status), PLUGIN_NAME);
    TSHttpTxnErrorBodySet(txnp, TSstrndup(ERROR_BODY.data(), ERROR_BODY.size()), ERROR_BODY.size(),
                          TSstrndup(ERROR_CTYPE.data(), ERROR_CTYPE.size()));
  }

  TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_RESPONSE_HDR_HOOK, contp);
}

void
set_location_header(TSMBuffer bufp, TSMLoc hdr_loc, std::string const &url)
{
  TSMLoc field = TSMimeHdrFieldFind(bufp, hdr_loc, TS_MIME_FIELD_LOCATION, TS_MIME_LEN_LOCATION);

  if (field == TS_NULL_MLOC) {
    if (TSMimeHdrFieldCreateNamed(bufp, hdr_loc, TS_MIME_FIELD_LOCATION, TS_MIME_LEN_LOCATION, &field) != TS_SUCCESS) {
      return;
    }
    TSMimeHdrFieldValueStringSet(bufp, hdr_loc, field, -1, url.data(), url.size());
    TSMimeHdrFieldAppend(bufp, hdr_loc, field);
  } else {
    TSMimeHdrFieldValueStringSet(bufp, hdr_loc, field, -1, url.data(), url.size());
  }

  Dbg(dbg_ctl, "set Location to %s", url.c_str());
  TSHandleMLocRelease(bufp, hdr_loc, field);
}

// Put the intervention status and redirect target on the response the client is
// about to receive.
void
finish_intervention(TSHttpTxn txnp, TxnContext *ctx)
{
  TSMBuffer bufp;
  TSMLoc    hdr_loc;

  if (TSHttpTxnClientRespGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
    Dbg(dbg_ctl, "unable to retrieve the client response header");
    return;
  }

  if (ctx->status != 0) {
    auto const status = static_cast<TSHttpStatus>(ctx->status);

    if (TSHttpHdrStatusGet(bufp, hdr_loc) != status) {
      char const *reason = TSHttpHdrReasonLookup(status);

      TSHttpHdrStatusSet(bufp, hdr_loc, status, txnp, PLUGIN_NAME);
      if (reason != nullptr) {
        TSHttpHdrReasonSet(bufp, hdr_loc, reason, strlen(reason));
      }
      Dbg(dbg_ctl, "set the response status to %d", ctx->status);
    }
  }

  if (!ctx->redirect_url.empty()) {
    set_location_header(bufp, hdr_loc, ctx->redirect_url);
  }

  TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
}

///////////////////////////////////////////////////////////////////////////////
// Request and response processing.
//
// Feed the client request to ModSecurity, running phases 1 and 2.
//
bool
process_request(TSHttpTxn txnp, TxnContext *ctx)
{
  TSMBuffer bufp;
  TSMLoc    hdr_loc;

  if (TSHttpTxnClientReqGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
    Dbg(dbg_ctl, "unable to retrieve the client request header");
    return false;
  }

  char client_ip[INET6_ADDRSTRLEN];
  char server_ip[INET6_ADDRSTRLEN];
  int  client_port = 0;
  int  server_port = 0;

  address_to_string(TSHttpTxnClientAddrGet(txnp), client_ip, client_port);
  address_to_string(TSHttpTxnIncomingAddrGet(txnp), server_ip, server_port);
  modsecurity::msc_process_connection(ctx->msc_txn, client_ip, client_port, server_ip, server_port);

  TSMLoc url_loc;

  if (TSHttpHdrUrlGet(bufp, hdr_loc, &url_loc) == TS_SUCCESS) {
    int         path_len  = 0;
    int         query_len = 0;
    char const *path      = TSUrlPathGet(bufp, url_loc, &path_len);
    char const *query     = TSUrlHttpQueryGet(bufp, url_loc, &query_len);
    std::string uri("/");

    if (path != nullptr) {
      uri.append(path, path_len);
    }
    if (query != nullptr && query_len > 0) {
      uri.append("?").append(query, query_len);
    }

    int         method_len = 0;
    char const *method     = TSHttpHdrMethodGet(bufp, hdr_loc, &method_len);
    std::string method_str(method != nullptr ? std::string(method, method_len) : std::string());

    modsecurity::msc_process_uri(ctx->msc_txn, uri.c_str(), method_str.c_str(), http_version(bufp, hdr_loc).c_str());
    TSHandleMLocRelease(bufp, hdr_loc, url_loc);
  }

  add_headers(bufp, hdr_loc, ctx->msc_txn, true);
  modsecurity::msc_process_request_headers(ctx->msc_txn);

  // The request body is never handed to ModSecurity, see the plugin
  // documentation for why. This call still has to be made so that the phase 2
  // rules run.
  modsecurity::msc_process_request_body(ctx->msc_txn);

  TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
  Dbg(dbg_ctl, "done processing the request");

  return true;
}

// Feed the origin response to ModSecurity, running phases 3 and 4.
bool
process_response(TSHttpTxn txnp, TxnContext *ctx)
{
  TSMBuffer bufp;
  TSMLoc    hdr_loc;

  if (TSHttpTxnServerRespGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
    Dbg(dbg_ctl, "unable to retrieve the server response header");
    return false;
  }

  add_headers(bufp, hdr_loc, ctx->msc_txn, false);

  std::string const  protocol = "HTTP/" + http_version(bufp, hdr_loc);
  TSHttpStatus const status   = TSHttpHdrStatusGet(bufp, hdr_loc);

  modsecurity::msc_process_response_headers(ctx->msc_txn, static_cast<int>(status), protocol.c_str());

  // As with the request body, the response body is not inspected.
  modsecurity::msc_process_response_body(ctx->msc_txn);

  TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
  Dbg(dbg_ctl, "done processing the response");

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// Continuation handlers.
//
int
txn_handler(TSCont contp, TSEvent event, void *edata)
{
  TSHttpTxn txnp     = static_cast<TSHttpTxn>(edata);
  auto     *ctx      = static_cast<TxnContext *>(TSContDataGet(contp));
  TSEvent   reenable = TS_EVENT_HTTP_CONTINUE;

  if (ctx == nullptr) {
    TSHttpTxnReenable(txnp, reenable);
    return TS_EVENT_NONE;
  }

  switch (event) {
  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    if (process_response(txnp, ctx)) {
      Intervention const iv = check_intervention(ctx->msc_txn);

      if (iv.disrupt) {
        apply_intervention(txnp, contp, ctx, iv);
        if (ctx->status != 0) {
          reenable = TS_EVENT_HTTP_ERROR;
        }
      }
    }
    break;

  case TS_EVENT_HTTP_SEND_RESPONSE_HDR:
    finish_intervention(txnp, ctx);
    break;

  case TS_EVENT_HTTP_TXN_CLOSE:
    TSContDataSet(contp, nullptr);
    delete ctx;
    TSContDestroy(contp);
    break;

  default:
    Dbg(dbg_ctl, "unexpected event %d", static_cast<int>(event));
    break;
  }

  TSHttpTxnReenable(txnp, reenable);

  return TS_EVENT_NONE;
}

// Start a ModSecurity transaction, run the request phase rules and register the
// hooks needed for the rest of the transaction. Returns true if ModSecurity
// wants the transaction disrupted with an internally generated response.
bool
inspect_request(TSHttpTxn txnp, RuleConfig *config)
{
  auto rules = config != nullptr ? config->rules() : nullptr;

  if (rules == nullptr) {
    Dbg(dbg_ctl, "no rules loaded, nothing to do");
    return false;
  }

  TSCont txn_contp = TSContCreate(txn_handler, nullptr);
  auto  *ctx       = new TxnContext();

  ctx->rules   = std::move(rules);
  ctx->msc_txn = modsecurity::msc_new_transaction(g_modsec, ctx->rules->get(), nullptr);

  if (ctx->msc_txn == nullptr) {
    TSError("[%s] failed to create a ModSecurity transaction", PLUGIN_NAME);
    delete ctx;
    TSContDestroy(txn_contp);
    return false;
  }

  TSContDataSet(txn_contp, ctx);
  TSHttpTxnHookAdd(txnp, TS_HTTP_TXN_CLOSE_HOOK, txn_contp);

  if (process_request(txnp, ctx)) {
    Intervention const iv = check_intervention(ctx->msc_txn);

    if (iv.disrupt) {
      apply_intervention(txnp, txn_contp, ctx, iv);
    }
  }

  // Only look at the origin response when the request was not disrupted.
  if (ctx->status == 0) {
    TSHttpTxnHookAdd(txnp, TS_HTTP_READ_RESPONSE_HDR_HOOK, txn_contp);
    return false;
  }

  return true;
}

int
read_request_handler(TSCont /* contp */, TSEvent /* event */, void *edata)
{
  TSHttpTxn txnp = static_cast<TSHttpTxn>(edata);

  TSHttpTxnReenable(txnp, inspect_request(txnp, g_config) ? TS_EVENT_HTTP_ERROR : TS_EVENT_HTTP_CONTINUE);

  return TS_EVENT_NONE;
}

int
lifecycle_handler(TSCont /* contp */, TSEvent event, void *edata)
{
  if (event != TS_EVENT_LIFECYCLE_MSG) {
    return TS_EVENT_NONE;
  }

  auto *msg = static_cast<TSPluginMsg *>(edata);

  if (strcmp(msg->tag, PLUGIN_NAME) != 0) {
    return TS_EVENT_NONE;
  }

  std::string_view data(msg->data_size > 0 ? static_cast<char const *>(msg->data) : "", msg->data_size);

  if (data != RELOAD_CMD) {
    TSError("[%s] unknown message '%.*s', expected '%.*s'", PLUGIN_NAME, static_cast<int>(data.size()), data.data(),
            static_cast<int>(RELOAD_CMD.size()), RELOAD_CMD.data());
    return TS_EVENT_NONE;
  }

  if (g_config != nullptr && g_config->reload()) {
    TSNote("[%s] reloaded the ModSecurity rules", PLUGIN_NAME);
  } else {
    TSError("[%s] reload failed, keeping the previously loaded rules", PLUGIN_NAME);
  }

  return TS_EVENT_NONE;
}

// Build a rule configuration out of the plugin arguments starting at "first".
RuleConfig *
make_config(int argc, char const *argv[], int first)
{
  if (argc <= first) {
    TSError("[%s] no ModSecurity rule file given", PLUGIN_NAME);
    return nullptr;
  }

  if (!init_modsecurity()) {
    return nullptr;
  }

  std::vector<std::string> files;

  for (int i = first; i < argc; ++i) {
    files.emplace_back(argv[i]);
  }

  auto *config = new RuleConfig();

  if (!config->init(files)) {
    delete config;
    return nullptr;
  }

  Dbg(dbg_ctl, "loaded %d rule file(s)", argc - first);

  return config;
}

} // end anonymous namespace

///////////////////////////////////////////////////////////////////////////////
// Global plugin entry points.
//
void
TSPluginInit(int argc, char const *argv[])
{
  TSPluginRegistrationInfo info;

  info.plugin_name   = PLUGIN_NAME;
  info.vendor_name   = PLUGIN_VENDOR;
  info.support_email = PLUGIN_SUPPORT;

  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[%s] plugin registration failed", PLUGIN_NAME);
    return;
  }

  g_config = make_config(argc, argv, 1);
  if (g_config == nullptr) {
    TSError("[%s] no usable rules, the plugin will not inspect any traffic", PLUGIN_NAME);
    return;
  }

  TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, TSContCreate(read_request_handler, nullptr));
  TSLifecycleHookAdd(TS_LIFECYCLE_MSG_HOOK, TSContCreate(lifecycle_handler, nullptr));
}

///////////////////////////////////////////////////////////////////////////////
// Remap plugin entry points.
//
TSReturnCode
TSRemapInit(TSRemapInterface *api_info, char *errbuf, int errbuf_size)
{
  CHECK_REMAP_API_COMPATIBILITY(api_info, errbuf, errbuf_size);
  Dbg(dbg_ctl, "remap plugin is successfully initialized");

  return TS_SUCCESS;
}

TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **ih, char *errbuf, int errbuf_size)
{
  // argv[0] and argv[1] are the "from" and "to" URLs of the remap rule.
  auto *config = make_config(argc, const_cast<char const **>(argv), 2);

  if (config == nullptr) {
    snprintf(errbuf, errbuf_size, "[%s] unable to load the ModSecurity rules", PLUGIN_NAME);
    return TS_ERROR;
  }

  *ih = config;

  return TS_SUCCESS;
}

void
TSRemapDeleteInstance(void *ih)
{
  delete static_cast<RuleConfig *>(ih);
}

TSRemapStatus
TSRemapDoRemap(void *ih, TSHttpTxn txnp, TSRemapRequestInfo * /* rri */)
{
  // A disrupted transaction is picked up by the core, which builds the response
  // from the status set by apply_intervention().
  inspect_request(txnp, static_cast<RuleConfig *>(ih));

  return TSREMAP_NO_REMAP;
}
