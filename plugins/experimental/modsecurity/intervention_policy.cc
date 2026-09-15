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

#include "intervention_policy.h"

#include <algorithm>
#include <string_view>

namespace modsecurity_plugin
{
Intervention
decide_intervention(bool disruptive, int status, char const *url)
{
  Intervention result;

  // Only a disruptive intervention blocks. libmodsecurity reports pass, allow and
  // every rule under SecRuleEngine DetectionOnly as not disruptive.
  if (!disruptive) {
    return result;
  }

  // A disruptive intervention blocks even when it arrives without a blocking
  // status of its own, using what ModSecurity does by default: a 302 for a
  // redirect, which would otherwise reach the origin with the Location header
  // stapled onto whatever the origin returned, and a 403 otherwise. The status is
  // settled before the redirect target is validated, so that dropping the target
  // cannot turn the intervention into a pass-through.
  result.disrupt = true;
  result.status  = status >= 300 ? status : (url != nullptr ? 302 : 403);

  // A redirect target may embed macro expansions of decoded request data, so it
  // can carry bytes that are not legal in a header value. Drop the redirect
  // whole rather than truncating it, which would leave a partially attacker
  // controlled target.
  if (url != nullptr) {
    std::string_view const target(url);

    if (std::none_of(target.begin(), target.end(), [](unsigned char c) { return c < 0x20 || c == 0x7f; })) {
      result.url = target;
    } else {
      result.url_dropped = true;
    }
  }

  return result;
}
} // namespace modsecurity_plugin
