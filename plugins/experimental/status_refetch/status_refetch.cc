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
#include "ts/remap.h"

#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <getopt.h>

#ifndef EXPORT
#define EXPORT extern "C" tsapi
#endif

namespace
{
constexpr const char *const PLUGIN_NAME       = "status_refetch";
constexpr char const *const stat_name_refetch = "plugin.status_refetch.refetch";

// plugin global
int stat_id_refetch = TS_ERROR;

struct Config {
  int maxage{0};               // seconds
  std::vector<int> statuses{}; // sorted TSHttpStatus

  static Config *fromArgs(int arg, char const *argv[]);

  bool
  is_valid() const
  {
    return !statuses.empty();
  }
};

void
create_stats()
{
  if (TS_ERROR == stat_id_refetch && TS_ERROR == TSStatFindName(stat_name_refetch, &stat_id_refetch)) {
    stat_id_refetch = TSStatCreate(stat_name_refetch, TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);
    if (TS_ERROR != stat_id_refetch) {
      TSDebug(PLUGIN_NAME, "Created stat '%s'", stat_name_refetch);
    }
  }
}

void
increment_stats()
{
  if (TS_ERROR != stat_id_refetch) {
    TSStatIntIncrement(stat_id_refetch, 1);
    TSDebug(PLUGIN_NAME, "Incrementing stat '%s'", stat_name_refetch);
  }
}

time_t
get_date_from_cached_hdr(TSHttpTxn txn)
{
  time_t date = 0;

  TSMLoc hdr_loc;
  TSMBuffer buf;
  if (TSHttpTxnCachedRespGet(txn, &buf, &hdr_loc) == TS_SUCCESS) {
    TSMLoc const date_loc = TSMimeHdrFieldFind(buf, hdr_loc, TS_MIME_FIELD_DATE, TS_MIME_LEN_DATE);
    if (TS_NULL_MLOC != date_loc) {
      date = TSMimeHdrFieldValueDateGet(buf, hdr_loc, date_loc);
      TSHandleMLocRelease(buf, hdr_loc, date_loc);
    }
    TSHandleMLocRelease(buf, TS_NULL_MLOC, hdr_loc);
  }

  return date;
}

int
main_handler(TSCont cont, TSEvent event, void *edata)
{
  TSHttpTxn txn = (TSHttpTxn)edata;
  int status;
  time_t now = 0;

  if (TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE == event && TS_SUCCESS == TSHttpTxnCacheLookupStatusGet(txn, &status)) {
    if (status == TS_CACHE_LOOKUP_HIT_FRESH) {
      TSMBuffer buf;
      TSMLoc loc;
      if (TS_SUCCESS == TSHttpTxnCachedRespGet(txn, &buf, &loc)) {
        TSHttpStatus const status = TSHttpHdrStatusGet(buf, loc);
        TSHandleMLocRelease(buf, TS_NULL_MLOC, loc);

        if (0 == now) {
          now = time(nullptr);
        }

        auto config = static_cast<Config const *const>(TSContDataGet(cont));

        if (std::binary_search(config->statuses.cbegin(), config->statuses.cend(), (int)status)) {
          time_t const date = get_date_from_cached_hdr(txn);

          if ((double)config->maxage < difftime(now, date)) {
            TSHttpTxnCacheLookupStatusSet(txn, TS_CACHE_LOOKUP_MISS);
            increment_stats();
            if (TSIsDebugTagSet(PLUGIN_NAME)) {
              int len         = 0;
              char *const url = TSHttpTxnEffectiveUrlStringGet(txn, &len);
              TSDebug(PLUGIN_NAME, "Forced refetch - %.*s %d", len, url, status);
              if (nullptr != url) {
                TSfree(url);
              }
            }
          }
        }
      }
    }
  }

  TSHttpTxnReenable(txn, TS_EVENT_HTTP_CONTINUE);
  return 0;
}

std::vector<int>
valuesFrom(char const *const str)
{
  std::set<int> stats;

  char const *ptr = str;
  char *end       = nullptr;

  while (true) {
    long int val = strtol(ptr, &end, 10);
    if (ptr == end) {
      break;
    }
    stats.insert((int)val);
    if ('\0' == *end) {
      break;
    }
    ptr = end + 1;
    end = nullptr;
  }

  return std::vector<int>(stats.begin(), stats.end());
}

Config *
Config::fromArgs(int argc, char const *argv[])
{
  Config *config = new Config;

  static const struct option longopts[] = {
    {"max-age", required_argument, NULL, 'm'},
    {"status", required_argument, NULL, 's'},
    {NULL, 0, NULL, 0},
  };

  // argv contains "to" and "from" urls. Skip over
  optind = 0;

  for (;;) {
    int const opt = getopt_long(argc, (char *const *)argv, "m:s:", longopts, NULL);

    if (-1 == opt) {
      break;
    }

    TSDebug(PLUGIN_NAME, "Processing arg: %c", opt);
    if (optarg) {
    }

    switch (opt) {
    case 'm':
      config->maxage = atoi(optarg);
      TSDebug(PLUGIN_NAME, "config maxage: %d", config->maxage);
      break;
    case 's':
      config->statuses = valuesFrom(optarg);
      if (!config->statuses.empty()) {
        std::ostringstream ostr;
        for (int stat : config->statuses) {
          ostr << " " << stat;
        }
        std::string const str = ostr.str();
        TSDebug(PLUGIN_NAME, "config statuses: %s", str.c_str());
      }
    default:
      break;
    }
  }

  if (!config->is_valid()) {
    delete config;
    config = nullptr;
  }

  return config;
}

} // namespace

// remap plugin
//
EXPORT
TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **ih, char *, int)
{
  Config *config = nullptr;
  if (2 < argc) {
    config = Config::fromArgs(argc - 1, (char const **)argv + 1);
  }
  if (nullptr == config) {
    return TS_ERROR;
  }

  *ih = static_cast<void *>(config);
  return TS_SUCCESS;
}

EXPORT
void
TSRemapDeleteInstance(void *ih)
{
  if (nullptr != ih) {
    Config *const config = static_cast<Config *>(ih);
    delete config;
  }
}

TSReturnCode
TSRemapInit(TSRemapInterface *, char *, int)
{
  TSDebug(PLUGIN_NAME, "remap initializing");
  return TS_SUCCESS;
}

// remap plugin
EXPORT
TSRemapStatus
TSRemapDoRemap(void *ih, TSHttpTxn /* txnp */, TSRemapRequestInfo * /* rri */)
{
  Config *const config   = static_cast<Config *>(ih);
  TSCont const main_cont = TSContCreate(main_handler, NULL);
  TSContDataSet(main_cont, static_cast<void *>(config));
  TSHttpHookAdd(TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, main_cont);

  return TSREMAP_NO_REMAP;
}

// global handler
void
TSPluginInit(int argc, char const *argv[])
{
  TSDebug(PLUGIN_NAME, "Starting plugin init");

  Config *const config = Config::fromArgs(argc, argv);
  if (nullptr == config) {
    TSError("[%s] Global plugin config failed", PLUGIN_NAME);
    return;
  } else {
    TSDebug(PLUGIN_NAME, "Global plugin initialization succeeded");
  }

  TSPluginRegistrationInfo info;
  info.plugin_name   = PLUGIN_NAME;
  info.vendor_name   = "Apache Software Foundation";
  info.support_email = "dev@trafficserver.apache.org";

  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[%s] Global plugin registration failed", PLUGIN_NAME);
    return;
  } else {
    TSDebug(PLUGIN_NAME, "Global plugin registration succeeded");
  }

  create_stats();

  TSCont const main_cont = TSContCreate(main_handler, NULL);
  TSContDataSet(main_cont, static_cast<void *>(config));
  TSHttpHookAdd(TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, main_cont);

  TSDebug(PLUGIN_NAME, "Global Plugin Init Complete");
}
