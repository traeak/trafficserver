/** @file

  Unit tests for the intervention policy of the modsecurity plugin.

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

#include "intervention_policy.h"

#include <catch2/catch_test_macros.hpp>

using modsecurity_plugin::decide_intervention;

TEST_CASE("A disruptive intervention keeps a blocking status", "[intervention]")
{
  auto const blocked = decide_intervention(true, 403, nullptr);

  CHECK(blocked.disrupt);
  CHECK(blocked.status == 403);
  CHECK(blocked.url.empty());
  CHECK_FALSE(blocked.url_dropped);
}

TEST_CASE("An intervention that is not disruptive never blocks", "[intervention]")
{
  // What libmodsecurity reports for pass, allow, and every rule under
  // SecRuleEngine DetectionOnly.
  auto const passed = decide_intervention(false, 200, nullptr);

  CHECK_FALSE(passed.disrupt);
  CHECK(passed.status == 200);

  // A status or a redirect target does not make it block either.
  auto const with_status = decide_intervention(false, 403, "https://www.example.com/");

  CHECK_FALSE(with_status.disrupt);
  CHECK(with_status.status == 200);
  CHECK(with_status.url.empty());
}

// libmodsecurity 3.0.14 always pairs a disruptive intervention with a blocking
// status, so these cases cannot be reached end to end with that version.
TEST_CASE("A disruptive intervention without a blocking status still blocks", "[intervention]")
{
  SECTION("With a 403 when there is no redirect")
  {
    auto const blocked = decide_intervention(true, 200, nullptr);

    CHECK(blocked.disrupt);
    CHECK(blocked.status == 403);
  }

  SECTION("With a 302 for a redirect")
  {
    auto const redirect = decide_intervention(true, 200, "https://www.example.com/");

    CHECK(redirect.disrupt);
    CHECK(redirect.status == 302);
    CHECK(redirect.url == "https://www.example.com/");
  }
}

TEST_CASE("A redirect with a status of its own keeps it", "[intervention]")
{
  auto const redirect = decide_intervention(true, 301, "https://www.example.com/");

  CHECK(redirect.disrupt);
  CHECK(redirect.status == 301);
  CHECK(redirect.url == "https://www.example.com/");
  CHECK_FALSE(redirect.url_dropped);
}

TEST_CASE("A redirect target carrying a control character is dropped", "[intervention]")
{
  SECTION("CR and LF")
  {
    auto const redirect = decide_intervention(true, 302, "https://www.example.com/?u=\r\nSet-Cookie: injected=1");

    CHECK(redirect.disrupt);
    CHECK(redirect.status == 302);
    CHECK(redirect.url.empty());
    CHECK(redirect.url_dropped);
  }

  SECTION("DEL")
  {
    auto const redirect = decide_intervention(true, 302, "https://www.example.com/\x7f");

    CHECK(redirect.url.empty());
    CHECK(redirect.url_dropped);
  }

  SECTION("Printable characters, percent encoding included, are kept")
  {
    auto const redirect = decide_intervention(true, 302, "https://www.example.com/?u=%0d%0a&v=~");

    CHECK(redirect.url == "https://www.example.com/?u=%0d%0a&v=~");
    CHECK_FALSE(redirect.url_dropped);
  }
}

// Dropping the target must not turn the redirect into a pass-through.
TEST_CASE("A dropped redirect target without a blocking status still blocks", "[intervention]")
{
  auto const redirect = decide_intervention(true, 200, "https://www.example.com/?u=\r\nSet-Cookie: injected=1");

  CHECK(redirect.disrupt);
  CHECK(redirect.status == 302);
  CHECK(redirect.url.empty());
  CHECK(redirect.url_dropped);
}
