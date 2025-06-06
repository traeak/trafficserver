/** @file

  A brief file description

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

#pragma once

#include "iocore/eventsystem/ConfigProcessor.h"
#include "iocore/net/SSLTypes.h"
#include "records/RecCore.h"

#include <set>
#include <openssl/ssl.h>
#include <mutex>
#include <unordered_map>
#include <utility>

struct SSLConfigParams;
struct SSLContextStorage;

/** Special things to do instead of use a context.
    In general an option will be associated with a @c nullptr context because
    the context is not used.
*/
enum class SSLCertContextOption {
  OPT_NONE,  ///< Nothing special. Implies valid context.
  OPT_TUNNEL ///< Just tunnel, don't terminate.
};

/**
   @brief Gather user provided settings from ssl_multicert.config in to this single struct
 */
struct SSLMultiCertConfigParams {
  SSLMultiCertConfigParams() : opt(SSLCertContextOption::OPT_NONE)
  {
    session_ticket_enabled = RecGetRecordInt("proxy.config.ssl.server.session_ticket.enable").value_or(0);
    session_ticket_number  = RecGetRecordInt("proxy.config.ssl.server.session_ticket.number").value_or(0);
  }

  int                  session_ticket_enabled; ///< session ticket enabled
  int                  session_ticket_number;  ///< amount of session tickets to issue for new TLSv1.3 connections
  ats_scoped_str       addr;                   ///< IPv[64] address to match
  ats_scoped_str       cert;                   ///< certificate
  ats_scoped_str       first_cert;             ///< the first certificate name when multiple cert files are in 'ssl_cert_name'
  ats_scoped_str       ca;                     ///< CA public certificate
  ats_scoped_str       key;                    ///< Private key
  ats_scoped_str       ocsp_response;          ///< prefetched OCSP response
  ats_scoped_str       dialog;                 ///< Private key dialog
  ats_scoped_str       servername;             ///< Destination server
  SSLCertContextOption opt;                    ///< SSLCertContext special handling option
};

struct ssl_ticket_key_t {
  unsigned char key_name[16];
  unsigned char hmac_secret[16];
  unsigned char aes_key[16];
};

struct ssl_ticket_key_block {
  unsigned         num_keys;
  ssl_ticket_key_t keys[];
};

using shared_ssl_ticket_key_block = std::shared_ptr<ssl_ticket_key_block>;

/** A certificate context.

    This holds data about a certificate and how it is used by the SSL logic. Current this is mainly
    the openSSL certificate and an optional action, which in turn is limited to just tunneling.

    Instances are passed around and returned when matching connections to certificates.

    Instances of this class are stored on a list and then referenced via index in that list so that
    there is exactly one place we can find all the @c SSL_CTX instances exactly once.

*/
struct SSLCertContext {
private:
  mutable std::mutex ctx_mutex;
  shared_SSL_CTX     ctx;

public:
  SSLCertContext() : ctx_mutex(), ctx(nullptr), opt(SSLCertContextOption::OPT_NONE), userconfig(nullptr), keyblock(nullptr) {}
  explicit SSLCertContext(SSL_CTX *c)
    : ctx_mutex(), ctx(c, SSL_CTX_free), opt(SSLCertContextOption::OPT_NONE), userconfig(nullptr), keyblock(nullptr)
  {
  }

  SSLCertContext(shared_SSL_CTX sc, SSLCertContextType ctx_type, const shared_SSLMultiCertConfigParams &u)
    : ctx_mutex(), ctx(std::move(sc)), ctx_type(ctx_type), opt(u->opt), userconfig(u), keyblock(nullptr)
  {
  }

  SSLCertContext(shared_SSL_CTX sc, SSLCertContextType ctx_type, const shared_SSLMultiCertConfigParams &u,
                 shared_ssl_ticket_key_block kb)
    : ctx_mutex(), ctx(std::move(sc)), ctx_type(ctx_type), opt(u->opt), userconfig(u), keyblock(std::move(kb))
  {
  }

  SSLCertContext(SSLCertContext const &other);
  SSLCertContext &operator=(SSLCertContext const &other);
  ~SSLCertContext() {}

  /// Threadsafe Functions to get and set shared SSL_CTX pointer
  shared_SSL_CTX getCtx();
  void           setCtx(shared_SSL_CTX sc);
  void           release();

  SSLCertContextType              ctx_type   = SSLCertContextType::GENERIC;
  SSLCertContextOption            opt        = SSLCertContextOption::OPT_NONE; ///< Special handling option.
  shared_SSLMultiCertConfigParams userconfig = nullptr;                        ///< User provided settings
  shared_ssl_ticket_key_block     keyblock   = nullptr;                        ///< session keys associated with this address
};

struct SSLCertLookup : public ConfigInfo {
  std::unique_ptr<SSLContextStorage> ssl_storage;
  std::unique_ptr<SSLContextStorage> ec_storage;

  shared_SSL_CTX ssl_default;
  bool           is_valid = true;

  int insert(const char *name, SSLCertContext const &cc);
  int insert(const IpEndpoint &address, SSLCertContext const &cc);

  /** Find certificate context by IP address.
      The IP addresses are taken from the socket @a s.
      Exact matches have priority, then wildcards. The destination address is preferred to the source address.
      @return @c A pointer to the matched context, @c nullptr if no match is found.
  */
  SSLCertContext *find(const IpEndpoint &address) const;

  /** Find certificate context by name (FQDN).
      Exact matches have priority, then wildcards. Only destination based matches are checked.
      @return @c A pointer to the matched context, @c nullptr if no match is found.
  */
  SSLCertContext *find(const std::string &name, SSLCertContextType ctxType = SSLCertContextType::GENERIC) const;

  // Return the last-resort default TLS context if there is no name or address match.
  SSL_CTX *
  defaultContext() const
  {
    return ssl_default.get();
  }

  unsigned        count(SSLCertContextType ctxType = SSLCertContextType::GENERIC) const;
  SSLCertContext *get(unsigned i, SSLCertContextType ctxType = SSLCertContextType::GENERIC) const;

  void register_cert_secrets(std::vector<std::string> const &cert_secrets, std::set<std::string> &lookup_names);
  void getPolicies(const std::string &secret_name, std::set<shared_SSLMultiCertConfigParams> &policies) const;

  SSLCertLookup();
  ~SSLCertLookup() override;

private:
  // Map cert_secret name to lookup keys
  std::unordered_map<std::string, std::vector<std::string>> cert_secret_registry;
};

void                  ticket_block_free(void *ptr);
ssl_ticket_key_block *ticket_block_alloc(unsigned count);
ssl_ticket_key_block *ticket_block_create(char *ticket_key_data, int ticket_key_len);
ssl_ticket_key_block *ssl_create_ticket_keyblock(const char *ticket_key_path);
