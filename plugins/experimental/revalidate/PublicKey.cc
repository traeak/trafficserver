/** @file

  Revalidate rule public key signature.

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

#include "PublicKey.h"

#include "revalidate.h"

#include <openssl/bio.h>
#include <openssl/err.h>

bool
PublicKey::is_valid() const
{
  return nullptr != key;
}

bool
PublicKey::verify(std::string_view const data, std::string_view const sig) const
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

bool
PublicKey::load(FILE *const fp)
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
