/** @file

  Exercise the TSLogField* API with string views that are not NUL-terminated
  where they end, an invalid replacement, and a too-small unmarshal buffer.

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

#include <ts/ts.h>

#include <string_view>
#include <tuple>
#include <vector>

namespace
{
constexpr char PLUGIN_NAME[] = "log_field_register";

// The name and symbol are prefixes of longer strings, so registering past the view would yield a different symbol.
constexpr std::string_view VIEW_NAME{std::string_view{"view field XXXX"}.substr(0, 10)};
constexpr std::string_view VIEW_SYMBOL{std::string_view{"lfrsXXXX"}.substr(0, 4)};
constexpr std::string_view KEPT_SYMBOL{"lfrk"};

// Not NUL-terminated, so marshaling must copy exactly the view's length.
constexpr char VIEW_VALUE[] = {'v', 'i', 'e', 'w'};

bool failed = false;

void
check(bool ok, const char *what)
{
  if (!ok) {
    TSError("[%s] FAIL: %s", PLUGIN_NAME, what);
    failed = true;
  }
}

int
marshal_view(TSHttpTxn /* txnp ATS_UNUSED */, char *buf)
{
  return TSLogStringMarshal(buf, std::string_view{VIEW_VALUE, sizeof(VIEW_VALUE)});
}

int
marshal_kept(TSHttpTxn /* txnp ATS_UNUSED */, char *buf)
{
  return TSLogStringMarshal(buf, "kept");
}

void
check_register()
{
  check(TSLogFieldRegister(VIEW_NAME, VIEW_SYMBOL, TS_LOG_TYPE_STRING, marshal_view, TSLogStringUnmarshal) == TS_SUCCESS,
        "register a field from views");
  check(TSLogFieldRegister("kept field", KEPT_SYMBOL, TS_LOG_TYPE_STRING, marshal_kept, TSLogStringUnmarshal) == TS_SUCCESS,
        "register a field to keep");
  check(TSLogFieldRegister("bad replacement", KEPT_SYMBOL, static_cast<TSLogType>(99), marshal_view, TSLogStringUnmarshal, true) ==
          TS_ERROR,
        "reject a replacement with an invalid type");
}

void
check_addr_unmarshal()
{
  std::vector<char> marshaled(TSLogAddrMarshal(nullptr, nullptr));

  TSLogAddrMarshal(marshaled.data(), nullptr);

  char  dest[2] = {'#', '#'};
  char *src     = marshaled.data();

  auto [read_len, write_len] = TSLogAddrUnmarshal(&src, dest, 1);
  check(read_len == -1 && write_len == -1, "reject a destination too small for an unset address");
  check(dest[1] == '#', "write nothing past the destination length");

  src                           = marshaled.data();
  std::tie(read_len, write_len) = TSLogAddrUnmarshal(&src, nullptr, 0);
  check(read_len == -1 && write_len == -1, "reject a null destination");
}

int
lifecycle_handler(TSCont /* contp ATS_UNUSED */, TSEvent event, void * /* edata ATS_UNUSED */)
{
  TSReleaseAssert(event == TS_EVENT_LIFECYCLE_LOG_INITIALIZED);
  check_register();
  check_addr_unmarshal();
  if (!failed) {
    TSNote("[%s] all checks passed", PLUGIN_NAME);
  }
  return 0;
}
} // namespace

void
TSPluginInit(int /* argc ATS_UNUSED */, const char ** /* argv ATS_UNUSED */)
{
  TSPluginRegistrationInfo info;

  info.plugin_name   = PLUGIN_NAME;
  info.vendor_name   = "Apache Software Foundation";
  info.support_email = "dev@trafficserver.apache.org";

  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[%s] plugin registration failed", PLUGIN_NAME);
    return;
  }

  TSLifecycleHookAdd(TS_LIFECYCLE_LOG_INITIALIZED_HOOK, TSContCreate(lifecycle_handler, nullptr));
}
