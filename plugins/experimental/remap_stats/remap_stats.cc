/** @file

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
#include "ts/experimental.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <search.h>
#include <mutex>
#include <map>
#include <string>
#include <string_view>

namespace {

constexpr char const * const PLUGIN_NAME = "remap_stats";
constexpr char const * const  DEBUG_TAG = PLUGIN_NAME;

typedef struct {
  bool post_remap_host;
  int txn_slot;
  TSStatPersistence persist_type;
  TSMutex stat_creation_mutex;
} config_t;

void
stat_add(char *name, TSMgmtInt amount, TSStatPersistence persist_type, TSMutex create_mutex)
{
	static std::map<std::string, int, std::less<>> stat_cache;
	static std::mutex cache_mutex;

  int stat_id = -1;
	std::string_view const nv(name);

	cache_mutex.lock();
	auto itfind = stat_cache.find(nv);
	
	if (stat_cache.end() == itfind) {

    TSMutexLock(create_mutex);
    if (TS_ERROR == TSStatFindName((const char *)name, &stat_id)) {
      stat_id = TSStatCreate((const char *)name, TS_RECORDDATATYPE_INT, persist_type, TS_STAT_SYNC_SUM);
      if (stat_id == TS_ERROR) {
        TSDebug(DEBUG_TAG, "Error creating stat_name: %s", name);
      } else {
        TSDebug(DEBUG_TAG, "Created stat_name: %s stat_id: %d", name, stat_id);
      }
    }
    TSMutexUnlock(create_mutex);

    if (0 <= stat_id) {
			stat_cache.insert(std::make_pair(std::string(nv), stat_id));
      TSDebug(DEBUG_TAG, "Cached stat_name: %s stat_id: %d", name, stat_id);
    }
  } else {
    stat_id = itfind->second;
  }
	
	cache_mutex.unlock();

  if (0 <= stat_id) {
    TSStatIntIncrement(stat_id, amount);
  } else {
    TSDebug(DEBUG_TAG, "stat error! stat_name: %s stat_id: %d", name, stat_id);
  }
}

// caller is responsible for the memory
char *
get_effective_host(TSHttpTxn txn)
{
  char *effective_url, *tmp;
  const char *host;
  int len;
  TSMBuffer buf;
  TSMLoc url_loc;

  buf = TSMBufferCreate();
  if (TS_SUCCESS != TSUrlCreate(buf, &url_loc)) {
    TSDebug(DEBUG_TAG, "unable to create url");
    TSMBufferDestroy(buf);
    return NULL;
  }
  tmp = effective_url = TSHttpTxnEffectiveUrlStringGet(txn, &len);
  TSUrlParse(buf, url_loc, (const char **)(&tmp), (const char *)(effective_url + len));
  TSfree(effective_url);
  host = TSUrlHostGet(buf, url_loc, &len);
  tmp  = TSstrndup(host, len);
  TSHandleMLocRelease(buf, TS_NULL_MLOC, url_loc);
  TSMBufferDestroy(buf);
  return tmp;
}

int
handle_read_req_hdr(TSCont cont, TSEvent event, void *edata)
{
  TSHttpTxn txn = (TSHttpTxn)edata;
  config_t *config;
  void *txnd;

  config = (config_t *)TSContDataGet(cont);
  txnd   = (void *)get_effective_host(txn); // low bit left 0 because we do not know that remap succeeded yet
  TSHttpTxnArgSet(txn, config->txn_slot, txnd);

  TSHttpTxnReenable(txn, TS_EVENT_HTTP_CONTINUE);
  TSDebug(DEBUG_TAG, "Read Req Handler Finished");
  return 0;
}

int
handle_post_remap(TSCont cont, TSEvent event, void *edata)
{
  TSHttpTxn txn = (TSHttpTxn)edata;
  config_t *config;
  void *txnd = (void *)0x01; // low bit 1 because we are post remap and thus success

  config = (config_t *)TSContDataGet(cont);

  if (config->post_remap_host) {
    TSHttpTxnArgSet(txn, config->txn_slot, txnd);
  } else {
    txnd = (void *)((uintptr_t)txnd | (uintptr_t)TSHttpTxnArgGet(txn, config->txn_slot)); // We need the hostname pre-remap
    TSHttpTxnArgSet(txn, config->txn_slot, txnd);
  }

  TSHttpTxnReenable(txn, TS_EVENT_HTTP_CONTINUE);
  TSDebug(DEBUG_TAG, "Post Remap Handler Finished");
  return 0;
}

#define MAX_STAT_LENGTH 8192
#define CREATE_STAT_NAME(s, h, b) snprintf(s, MAX_STAT_LENGTH, "plugin.%s.%s.%s", PLUGIN_NAME, h, b)

int
handle_txn_close(TSCont cont, TSEvent event, void *edata)
{
  TSHttpTxn txn = (TSHttpTxn)edata;
  config_t *config;
  void *txnd;
  int status_code = 0;
  TSMBuffer buf;
  TSMLoc hdr_loc;
  TSMgmtInt out_bytes, in_bytes;
  char const *remap;
	char *hostname;
  static char const * const unknown = "unknown";
  char stat_name[MAX_STAT_LENGTH];

  config = (config_t *)TSContDataGet(cont);
  txnd   = TSHttpTxnArgGet(txn, config->txn_slot);

  hostname = (char *)((uintptr_t)txnd & (~((uintptr_t)0x01))); // Get hostname

  if (txnd) {
    if ((uintptr_t)txnd & 0x01) // remap succeeded?
    {
      if (!config->post_remap_host) {
        remap = hostname;
      } else {
        remap = get_effective_host(txn);
      }

      if (!remap) {
        remap = unknown;
      }

      int const creqhdrbytes      = TSHttpTxnClientReqHdrBytesGet(txn);
      int64_t const creqbodybytes = TSHttpTxnClientReqBodyBytesGet(txn);

      if (0 <= creqhdrbytes && 0 <= creqbodybytes) {
        in_bytes = (TSMgmtInt)creqhdrbytes;
        in_bytes += (TSMgmtInt)creqbodybytes;
      } else {
        in_bytes = 0;
      }

      CREATE_STAT_NAME(stat_name, remap, "in_bytes");
      stat_add(stat_name, in_bytes, config->persist_type, config->stat_creation_mutex);

      int const cresphdrbytes      = TSHttpTxnClientRespHdrBytesGet(txn);
      int64_t const crespbodybytes = TSHttpTxnClientRespBodyBytesGet(txn);

      if (0 <= cresphdrbytes && 0 <= crespbodybytes) {
        out_bytes = (TSMgmtInt)cresphdrbytes;
        out_bytes += (TSMgmtInt)crespbodybytes;
      } else {
        out_bytes = 0;
      }

      CREATE_STAT_NAME(stat_name, remap, "out_bytes");
      stat_add(stat_name, out_bytes, config->persist_type, config->stat_creation_mutex);

      if (TSHttpTxnClientRespGet(txn, &buf, &hdr_loc) == TS_SUCCESS) {
        status_code = (int)TSHttpHdrStatusGet(buf, hdr_loc);
        TSHandleMLocRelease(buf, TS_NULL_MLOC, hdr_loc);

        if (status_code < 200) {
          CREATE_STAT_NAME(stat_name, remap, "status_other");
        } else if (status_code <= 299) {
          CREATE_STAT_NAME(stat_name, remap, "status_2xx");
        } else if (status_code <= 399) {
          CREATE_STAT_NAME(stat_name, remap, "status_3xx");
        } else if (status_code <= 499) {
          CREATE_STAT_NAME(stat_name, remap, "status_4xx");
        } else if (status_code <= 599) {
          CREATE_STAT_NAME(stat_name, remap, "status_5xx");
        } else {
          CREATE_STAT_NAME(stat_name, remap, "status_other");
        }

        stat_add(stat_name, 1, config->persist_type, config->stat_creation_mutex);
      } else {
        CREATE_STAT_NAME(stat_name, remap, "status_unknown");
        stat_add(stat_name, 1, config->persist_type, config->stat_creation_mutex);
      }

      if (remap != unknown) {
        TSfree((char*)remap);
      }
    } else if (hostname) {
      TSfree(hostname);
    }
  }

  TSHttpTxnReenable(txn, TS_EVENT_HTTP_CONTINUE);
  TSDebug(DEBUG_TAG, "Handler Finished");
  return 0;
}

} // namespace

void
TSPluginInit(int argc, const char *argv[])
{
  TSPluginRegistrationInfo info;
  TSCont pre_remap_cont, post_remap_cont, global_cont;
  config_t *config;

  info.plugin_name   = PLUGIN_NAME;
  info.vendor_name   = "Apache Software Foundation";
  info.support_email = "dev@trafficserver.apache.org";

  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[remap_stats] Plugin registration failed");

    return;
  } else {
    TSDebug(DEBUG_TAG, "Plugin registration succeeded");
  }

  config                      = (config_t*)TSmalloc(sizeof(config_t));
  config->post_remap_host     = false;
  config->persist_type        = TS_STAT_NON_PERSISTENT;
  config->stat_creation_mutex = TSMutexCreate();

  if (argc > 1) {
    int c;
    static const struct option longopts[] = {
      {"post-remap-host", no_argument, NULL, 'P'}, {"persistent", no_argument, NULL, 'p'}, {NULL, 0, NULL, 0}};

    while ((c = getopt_long(argc, (char *const *)argv, "Pp", longopts, NULL)) != -1) {
      switch (c) {
      case 'P':
        config->post_remap_host = true;
        TSDebug(DEBUG_TAG, "Using post remap hostname");
        break;
      case 'p':
        config->persist_type = TS_STAT_PERSISTENT;
        TSDebug(DEBUG_TAG, "Using persistent stats");
        break;
      default:
        break;
      }
    }
  }

  TSHttpTxnArgIndexReserve(PLUGIN_NAME, "txn data", &(config->txn_slot));

  if (!config->post_remap_host) {
    pre_remap_cont = TSContCreate(handle_read_req_hdr, NULL);
    TSContDataSet(pre_remap_cont, (void *)config);
    TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, pre_remap_cont);
  }

  post_remap_cont = TSContCreate(handle_post_remap, NULL);
  TSContDataSet(post_remap_cont, (void *)config);
  TSHttpHookAdd(TS_HTTP_POST_REMAP_HOOK, post_remap_cont);

  global_cont = TSContCreate(handle_txn_close, NULL);
  TSContDataSet(global_cont, (void *)config);
  TSHttpHookAdd(TS_HTTP_TXN_CLOSE_HOOK, global_cont);

  TSDebug(DEBUG_TAG, "Init complete");
}
