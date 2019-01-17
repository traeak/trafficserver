/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/*
 * This plugin looks for range requests and then creates a new
 * cache key url so that each individual range requests is written
 * to the cache as a individual object so that subsequent range
 * requests are read accross different disk drives reducing I/O
 * wait and load averages when there are large numbers of range
 * requests.
 */

#include "ts/ts.h"
#include "ts/experimental.h"
#include "ts/remap.h"

#include <atomic>
#include <cassert>
#include <getopt.h>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>

#ifndef PLUGIN_NAME
#define PLUGIN_NAME "collapsed_connection"
#endif

#define DEBUG_LOG(fmt, ...) TSDebug(PLUGIN_NAME, "[%s:%d] %s(): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__);

#define ERROR_LOG(fmt, ...)                                                   \
  TSError("[%s:%d] %s(): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
  DEBUG_LOG(fmt, ##__VA_ARGS__)

namespace
{
struct KeyState {
  TSHRTime timestamp_ms{0};
  std::string url_key{};
  std::atomic<TSHttpStatus> http_status{TS_HTTP_STATUS_NONE};

  explicit KeyState(std::string keyin) : timestamp_ms(TShrtime()), url_key(std::string(keyin)) {}
};

struct RemapState {
  int retry_delay_ms{50};
  int timeout_ms{1000};

  // in progress key lookup lock
  std::mutex mutex_fetch;

  // urls currently in CACHE_MISS or CACHE_HIT_STALE
  // std::less<> makes this find usable with std::string_view
  std::map<std::string, std::shared_ptr<KeyState>, std::less<>> urls_fetch{};
};

struct TxnState {
  RemapState *const remap_state{nullptr};
  bool is_leader{false};
  TSHttpTxn txnp{nullptr};
  std::shared_ptr<KeyState> key_state{};

  explicit TxnState(RemapState *const rstate, TSHttpTxn const txnpin, std::shared_ptr<KeyState> const &kstate)
    : remap_state(rstate), txnp(txnpin), key_state(kstate)
  {
  }
};

struct ExpireState {
  RemapState *const remap_state{nullptr};
  std::shared_ptr<KeyState> key_state{};

  explicit ExpireState(RemapState *const rstate, std::shared_ptr<KeyState> kstate)
    : remap_state(rstate), key_state(std::move(kstate))
  {
  }

  void
  release_key_state()
  {
    using FetchMap = std::map<std::string, std::shared_ptr<KeyState>, std::less<>>;

    std::lock_guard<std::mutex> const guard(remap_state->mutex_fetch);
    FetchMap &fetchmap = remap_state->urls_fetch;
    auto const itfind(fetchmap.find(key_state->url_key));

    if (fetchmap.end() != itfind) {
      std::shared_ptr<KeyState> const &keyfound = itfind->second;
      if (keyfound->timestamp_ms == key_state->timestamp_ms) { // owner check
        fetchmap.erase(itfind);
      }
    }
  }
};

int
expire_handler(TSCont contp, TSEvent /* event */, void * /* edata */)
{
  DEBUG_LOG("expire_handler: heartbeat");
  auto const estate = static_cast<ExpireState *>(TSContDataGet(contp));
  estate->release_key_state();
  delete estate;
  TSContDataSet(contp, nullptr);
  TSContDestroy(contp);
  return TS_EVENT_CONTINUE;
}

int
retry_handler(TSCont contp, TSEvent /* event */, void * /* edata */)
{
  auto const tstate = static_cast<TxnState *>(TSContDataGet(contp));
  TSAssert(nullptr != tstate);
  TSAssert(nullptr != tstate->txnp);

  RemapState *const rstate  = tstate->remap_state;
  TSHttpStatus const status = tstate->key_state->http_status.load();

  if (TS_HTTP_STATUS_NONE != status) {
    // std::cerr << "retry_handler: bailing" << std::endl;
    DEBUG_LOG("retry handler: bailing");
    TSContDataSet(contp, nullptr);
    TSContDestroy(contp);

    if (TS_HTTP_STATUS_OK == status) {
      // std::cerr << "retry_handler: allowing through" << std::endl;
      DEBUG_LOG("retry handler: allowing through");

      TSHttpTxnReenable(tstate->txnp, TS_EVENT_HTTP_CONTINUE);
      return TS_EVENT_CONTINUE;
    } else {
      DEBUG_LOG("retry_handler: cloning return status");

      TSHttpTxnStatusSet(tstate->txnp, status);
      TSHttpTxnReenable(tstate->txnp, TS_EVENT_HTTP_ERROR);
      return TS_EVENT_ERROR;
    }
  } else {
    DEBUG_LOG("retry_handler: scheduling retry");
    // std::cerr << "retry_handler: scheduling retry" << std::endl;
    TSContSchedule(contp, rstate->retry_delay_ms, TS_THREAD_POOL_DEFAULT);
    return TS_EVENT_NONE;
  }
}

// This fills the cache even if the original group leader aborts.
int
client_reader(TSCont contp, TSEvent event, void * /* edata */)
{
  // check for connection closed
  if (TSVConnClosedGet(contp)) {
    TSContDestroy(contp);
    return 0;
  }

  TSVIO const input_vio = TSVConnWriteVIOGet(contp);

  switch (event) {
  case TS_EVENT_ERROR:
    DEBUG_LOG("Error event");
    TSContCall(TSVIOContGet(input_vio), TS_EVENT_ERROR, input_vio);
    break;
  case TS_EVENT_VCONN_READ_COMPLETE:
    DEBUG_LOG("Read complete");
    break;
  case TS_EVENT_VCONN_READ_READY:
  case TS_EVENT_IMMEDIATE:
    if (TSVIOBufferGet(input_vio)) {
      TSIOBufferReader const reader = TSVIOReaderGet(input_vio);
      int64_t const avail           = TSIOBufferReaderAvail(reader);
      if (0 < avail) {
        TSIOBufferReaderConsume(reader, avail);
        TSVIONDoneSet(input_vio, TSVIONDoneGet(input_vio) + avail);
      }

      if (0 < TSVIONTodoGet(input_vio)) {
        TSContCall(TSVIOContGet(input_vio), TS_EVENT_VCONN_WRITE_READY, input_vio);
      } else {
        TSContCall(TSVIOContGet(input_vio), TS_EVENT_VCONN_WRITE_COMPLETE, input_vio);
      }
    }
    break;
  default:
    break;
  }

  return 0;
}

void
resolve_key_state(TxnState *const tstate, TSHttpStatus const status)
{
  DEBUG_LOG("resolve_key_state setting status to: %d", status);
  if (status != TS_HTTP_STATUS_OK) {
    std::cerr << "rksstat setting status to: " << status << std::endl;
  }
  tstate->key_state->http_status = status;
}

void
resolve_key_state(TxnState *const tstate, TSHttpTxn const txnp)
{
  TSMBuffer buffer    = nullptr;
  TSMLoc hdr_loc      = nullptr;
  TSHttpStatus status = TS_HTTP_STATUS_NONE;

  if (TS_SUCCESS == TSHttpTxnServerRespGet(txnp, &buffer, &hdr_loc)) {
    status = TSHttpHdrStatusGet(buffer, hdr_loc);
    TSHandleMLocRelease(buffer, nullptr, hdr_loc);
  }

  if (TS_HTTP_STATUS_NONE == status) {
    status = TS_HTTP_STATUS_BAD_GATEWAY;
  }

  DEBUG_LOG("resolve_key_state setting status to: %d", status);
  if (status != TS_HTTP_STATUS_OK) {
    std::cerr << "rks/txnp setting status to: " << status << std::endl;
  }
  tstate->key_state->http_status = status;
}

/**
 * main transaction event handler
 */
int
main_handler(TSCont contp, TSEvent event, void *edata)
{
  auto const txnp = static_cast<TSHttpTxn>(edata);

  switch (event) {
  case TS_EVENT_HTTP_POST_REMAP: {
    auto const rstate = static_cast<RemapState *>(TSContDataGet(contp));

    int url_len     = 0;
    char *const url = TSHttpTxnEffectiveUrlStringGet(txnp, &url_len);
    TSAssert(nullptr != url);

    std::string_view const urlview(url, url_len);

    using FetchMap     = std::map<std::string, std::shared_ptr<KeyState>, std::less<>>;
    FetchMap &fetchmap = rstate->urls_fetch;

    rstate->mutex_fetch.lock();
    auto const itfind(fetchmap.find(urlview));

    if (fetchmap.end() == itfind) { // group leader

      DEBUG_LOG("Creating group leader");
      // std::cerr << "creating group leader" << std::endl;

      std::shared_ptr<KeyState> key_state = std::make_shared<KeyState>(std::string(url, url_len));
      fetchmap.insert(std::make_pair(key_state->url_key, key_state));

      rstate->mutex_fetch.unlock();

      auto const tstate = new TxnState(rstate, txnp, key_state);
      tstate->is_leader = true;

      // override the continuation data
      TSContDataSet(contp, tstate);

      TSHttpTxnHookAdd(txnp, TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, contp);
      TSHttpTxnHookAdd(txnp, TS_HTTP_TXN_CLOSE_HOOK, contp);

      // start expiration continuation
      TSCont const cont_expire = TSContCreate(expire_handler, TSMutexCreate());
      auto const estate        = new ExpireState(rstate, std::move(key_state));
      TSContDataSet(cont_expire, estate);
      TSContSchedule(cont_expire, rstate->timeout_ms, TS_THREAD_POOL_TASK);
    } else { // group member

      DEBUG_LOG("Creating group member");
      // std::cerr << "creating group member" << std::endl;

      std::shared_ptr<KeyState> const &key_state = itfind->second;
      auto const tstate                          = new TxnState(rstate, txnp, key_state);

      rstate->mutex_fetch.unlock();

      // override the continuation data
      TSContDataSet(contp, tstate);

      TSHttpTxnHookAdd(txnp, TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, contp);
      TSHttpTxnHookAdd(txnp, TS_HTTP_TXN_CLOSE_HOOK, contp);

      // start retry loop
      TSCont const cont_retry = TSContCreate(retry_handler, TSMutexCreate());
      TSContDataSet(cont_retry, tstate);
      retry_handler(cont_retry, TS_EVENT_NONE, nullptr);
      //      TSContSchedule(cont_retry, rstate->retry_delay_ms, TS_THREAD_POOL_DEFAULT);
      return TS_EVENT_NONE;
    }

    TSfree(url);

  } break;

  case TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE: {
    int status = TS_ERROR;
    TSHttpTxnCacheLookupStatusGet(txnp, &status);
    switch (status) {
    case TS_CACHE_LOOKUP_HIT_FRESH: {
      auto const tstate = static_cast<TxnState *>(TSContDataGet(contp));
      if (tstate->is_leader) {
        DEBUG_LOG("destroying group leader (CACHED)");
        resolve_key_state(tstate, TS_HTTP_STATUS_OK);
        delete tstate;
        TSContDataSet(contp, nullptr);
      }
    } break;

    case TS_CACHE_LOOKUP_MISS: {
      auto const tstate = static_cast<TxnState *>(TSContDataGet(contp));
      if (tstate->is_leader) {
        // Defer to parent response
        TSHttpTxnHookAdd(txnp, TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
      }
    } break;

    case TS_CACHE_LOOKUP_HIT_STALE: {
      auto const tstate = static_cast<TxnState *>(TSContDataGet(contp));
      if (tstate->is_leader) {
        // Defer to parent response
        TSHttpTxnHookAdd(txnp, TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
      } else if (TS_CACHE_LOOKUP_HIT_STALE == status) {
        // Threshold crossed as leader got a FRESH
        TSHttpTxnCacheLookupStatusSet(txnp, TS_CACHE_LOOKUP_HIT_FRESH);
      }
    } break;
    default: {
    } break;
    }
  } break;

  // Only leader is allowed to interact with parent
  case TS_EVENT_HTTP_READ_RESPONSE_HDR: {
    TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_RESPONSE_HDR_HOOK, contp);

    auto const tstate = static_cast<TxnState *>(TSContDataGet(contp));
    if (nullptr != tstate) {
      assert(tstate->is_leader);
      TSMBuffer buffer = nullptr;
      TSMLoc hdr_loc   = nullptr;

      // spin off a cache fetcher in case the group leader's client leaves
      if (TS_SUCCESS == TSHttpTxnServerRespGet(txnp, &buffer, &hdr_loc)) {
        if (TSHttpTxnIsCacheable(txnp, nullptr, buffer)) {
          TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_CLIENT_HOOK, TSTransformCreate(client_reader, txnp));
        }
        TSHandleMLocRelease(buffer, nullptr, hdr_loc);
      }
    }
  } break;

    // at this point the headers should be cached.
  case TS_EVENT_HTTP_SEND_RESPONSE_HDR: {
    // The parent gave us an answer
    auto const tstate = static_cast<TxnState *>(TSContDataGet(contp));
    if (nullptr != tstate) {
      assert(tstate->is_leader);
      DEBUG_LOG("destroying group leader (RECV)");

      resolve_key_state(tstate, txnp);
      delete tstate;
      TSContDataSet(contp, nullptr);
    }
  } break;

  case TS_EVENT_HTTP_TXN_CLOSE: {
    auto const tstate = static_cast<TxnState *>(TSContDataGet(contp));
    if (nullptr != tstate) {
      if (tstate->is_leader) {
        DEBUG_LOG("destroying group leader (CLOSE)");
        resolve_key_state(tstate, txnp);
      }
      TSContDataSet(contp, nullptr);
      delete tstate;
    }
    TSContDestroy(contp);
  } break;
  default:
    break;
  }

  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  return TS_EVENT_CONTINUE;
}

/**
 * combined entry point
 */
void
handle_request(TSHttpTxn txnp, RemapState *const remap_state)
{
  // create continuation with the txn specific data
  TSCont const contp = TSContCreate(main_handler, nullptr);
  TSContDataSet(contp, static_cast<void *>(remap_state));

  // do work at the post remap hook stage
  TSHttpTxnHookAdd(txnp, TS_HTTP_POST_REMAP_HOOK, contp);
}

/**
 * global entry point
 */
int
global_handler(TSCont contp, TSEvent, void *edata)
{
  auto const txnp = static_cast<TSHttpTxn>(edata);

  TSMBuffer hdr_bufp = nullptr;
  TSMLoc hdr_loc     = nullptr;

  // only interested in GET methods
  if (TS_SUCCESS == TSHttpTxnClientReqGet(txnp, &hdr_bufp, &hdr_loc)) {
    int method_len           = 0;
    char const *const method = TSHttpHdrMethodGet(hdr_bufp, hdr_loc, &method_len);

    if (TS_HTTP_METHOD_GET == method) {
      auto const state = static_cast<RemapState *>(TSContDataGet(contp));
      handle_request(txnp, state);
    }

    TSHandleMLocRelease(hdr_bufp, nullptr, hdr_loc);
  }

  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  return TS_EVENT_NONE;
}

} // namespace

/**
 * Remap entry point.
 */
TSRemapStatus
TSRemapDoRemap(void *ih, TSHttpTxn txnp, TSRemapRequestInfo *rri)
{
  TSAssert(nullptr != ih);

  // sample: only interested in GET methods
  int method_len           = 0;
  char const *const method = TSHttpHdrMethodGet(rri->requestBufp, rri->requestHdrp, &method_len);

  if (TS_HTTP_METHOD_GET == method) {
    // retrieve any per remap config (and/or shared data)
    auto const state = static_cast<RemapState *>(ih);
    handle_request(txnp, state);
  }

  return TSREMAP_NO_REMAP;
}

//
// plugin setup and teardown
//

/**
 *
 */
void
TSRemapOSResponse(void *ih, TSHttpTxn rh, int os_response_type)
{
}

/**
 * New remap rule
 */
TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **ih, char *errbuf, int errbuf_size)
{
  // create new config (and/or shared data)
  RemapState *const remap_state = new RemapState;
  //  remap_state->fromArgs(argc - 1, static_cast<char const *const *>(argv + 1));
  *ih = static_cast<void *>(remap_state);
  return TS_SUCCESS;
}

/**
 * Delete remap rule -- however never called
 */
void
TSRemapDeleteInstance(void *ih)
{
  if (nullptr != ih) {
    auto const remap_state = static_cast<RemapState *>(ih);
    delete remap_state;
  }
}

/**
 * remap init
 */
TSReturnCode
TSRemapInit(TSRemapInterface *api_info, char *errbug, int errbuf_size)
{
  DEBUG_LOG("initialized.");
  return TS_SUCCESS;
}

/**
 * global plugin
 */
void
TSPluginInit(int argc, char const *argv[])
{
  TSPluginRegistrationInfo info;
  info.plugin_name   = const_cast<char *>(PLUGIN_NAME);
  info.vendor_name   = const_cast<char *>("Apache Software Foundation");
  info.support_email = const_cast<char *>("dev@trafficserver.apache.org");

  if (TS_SUCCESS != TSPluginRegister(&info)) {
    ERROR_LOG("Plugin registration failed.\n");
    ERROR_LOG("Unable to initialize plugin (disabled).\n");
    return;
  }

  // also could be TSMutexCreate() instead of nullptr
  TSCont const contp = TSContCreate(global_handler, nullptr);

  // setup global config
  auto const remap_state = new RemapState;
  //  remap_state->fromArgs(argc, static_cast<char const *const *>(argv));

  TSContDataSet(contp, static_cast<void *>(remap_state));

  TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, contp);

  DEBUG_LOG("global plugin configured");
}
