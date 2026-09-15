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

#pragma once

#include <string>

namespace modsecurity_plugin
{
// What the plugin does with a ModSecurity intervention.
struct Intervention {
  bool        disrupt = false;
  int         status  = 200;
  std::string url;                 // redirect target, empty when there is none or it was dropped
  bool        url_dropped = false; // the redirect target carried a control character
};

// Decide what to do with an intervention from its disruptive flag, status and
// redirect target alone. It makes no Traffic Server calls, so that the decision
// can be unit tested. "url" may be null.
Intervention decide_intervention(bool disruptive, int status, char const *url);
} // namespace modsecurity_plugin
