/** @file

  An example plugin for accept object protocol set API.

  This clones the protocol sets attached to all the accept objects and unregisters HTTP/2 from those
  copies.  The protocol set for incoming connections that match a list of domains are replaced with
  the copy, effectively disabling HTTP/2 for those domains.

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

#include <unordered_set>
#include <string>
#include <cstring>
#include <openssl/ssl.h>

#define PLUGIN_NAME "disable_http2"

namespace
{
DbgCtl dbg_ctl{PLUGIN_NAME};
}

// Map of domains to tweak.
using DomainSet = std::unordered_set<std::string>;
DomainSet Domains;

int
CB_SNI(TSCont /* contp ATS_UNUSED */, TSEvent, void *cb_data)
{
  auto            vc       = static_cast<TSVConn>(cb_data);
  TSSslConnection ssl_conn = TSVConnSslConnectionGet(vc);
  auto           *ssl      = reinterpret_cast<SSL *>(ssl_conn);
  char const     *sni      = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  if (sni) {
    if (Domains.find(sni) != Domains.end()) {
      Dbg(dbg_ctl, "Disable H2 for SNI=%s", sni);
      TSVConnProtocolDisable(vc, TS_ALPN_PROTOCOL_HTTP_2_0);
    }
  }

  TSVConnReenable(vc);
  return TS_SUCCESS;
}

void
TSPluginInit(int argc, char const *argv[])
{
  int                      ret;
  TSPluginRegistrationInfo info;

  info.plugin_name   = PLUGIN_NAME;
  info.vendor_name   = "Apache Software Foundation";
  info.support_email = "dev@trafficserver.apache.org";
  ret                = TSPluginRegister(&info);

  if (ret != TS_SUCCESS) {
    TSError("[%s] registration failed", PLUGIN_NAME);
    return;
  } else if (argc < 2) {
    TSError("[%s] Usage %s.so servername1 servername2 ... ", PLUGIN_NAME, PLUGIN_NAME);
    return;
  } else {
    Dbg(dbg_ctl, "registration succeeded");
  }

  for (int i = 1; i < argc; i++) {
    Dbg(dbg_ctl, "%s added to the No-H2 list", argv[i]);
    Domains.emplace(std::string(argv[i], strlen(argv[i])));
  }
  // These callbacks do not modify any state so no lock is needed.
  TSCont cb_sni = TSContCreate(&CB_SNI, nullptr);

  TSHttpHookAdd(TS_SSL_SERVERNAME_HOOK, cb_sni);
}
