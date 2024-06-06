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

#pragma once

#include <cstdio>
#include <filesystem>
#include <memory>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string_view>
#include <vector>

struct PublicKey {
  EVP_PKEY *key{nullptr};

  PublicKey() = default;
  PublicKey(EVP_PKEY *const ikey) { key = ikey; }
  PublicKey(PublicKey &&)                 = default;
  PublicKey(PublicKey const &)            = delete;
  PublicKey &operator=(PublicKey &&)      = default;
  PublicKey &operator=(PublicKey const &) = delete;
  ~PublicKey()
  {
    if (nullptr != key) {
      EVP_PKEY_free(key);
    }
  }

  bool load(FILE *const fp);
  bool is_valid() const;

  bool verify(std::string_view const data, std::string_view const sig) const;
};

// Load public keys from path.
std::shared_ptr<std::vector<PublicKey>> load_keys_from(std::filesystem::path const &path);
