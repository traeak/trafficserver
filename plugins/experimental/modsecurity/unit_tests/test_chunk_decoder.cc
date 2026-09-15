/** @file

  Unit tests for the chunked request-body decoder of the modsecurity plugin.

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

#include "chunk_decoder.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

using modsecurity_plugin::ChunkDecoder;
using State = modsecurity_plugin::ChunkDecoder::State;

namespace
{
// Decode the whole input at once.
State
decode(std::string_view input, std::string &out)
{
  ChunkDecoder decoder;
  return decoder.feed(input, out);
}
} // namespace

TEST_CASE("A single chunk decodes to its body", "[chunk]")
{
  std::string out;
  CHECK(decode("5\r\nhello\r\n0\r\n\r\n", out) == State::Done);
  CHECK(out == "hello");
}

TEST_CASE("Several chunks are concatenated", "[chunk]")
{
  std::string out;
  CHECK(decode("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", out) == State::Done);
  CHECK(out == "hello world");
}

TEST_CASE("A hex chunk size is read as hexadecimal", "[chunk]")
{
  std::string       out;
  std::string const body(255, 'x');
  CHECK(decode("ff\r\n" + body + "\r\n0\r\n\r\n", out) == State::Done);
  CHECK(out == body);
}

TEST_CASE("Chunk extensions are ignored", "[chunk]")
{
  std::string out;
  CHECK(decode("5;name=value\r\nhello\r\n0\r\n\r\n", out) == State::Done);
  CHECK(out == "hello");
}

TEST_CASE("Trailer lines are consumed", "[chunk]")
{
  std::string out;
  CHECK(decode("5\r\nhello\r\n0\r\nX-Checksum: abc\r\n\r\n", out) == State::Done);
  CHECK(out == "hello");
}

TEST_CASE("Input split across feeds decodes the same", "[chunk]")
{
  std::string const message = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";

  for (size_t split = 1; split < message.size(); ++split) {
    ChunkDecoder decoder;
    std::string  out;
    State        state = decoder.feed(std::string_view(message).substr(0, split), out);

    if (state == State::Incomplete) {
      state = decoder.feed(std::string_view(message).substr(split), out);
    }
    CHECK(state == State::Done);
    CHECK(out == "hello world");
  }
}

TEST_CASE("Feeding one byte at a time decodes the same", "[chunk]")
{
  std::string const message = "3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n";
  ChunkDecoder      decoder;
  std::string       out;
  State             state = State::Incomplete;

  for (char const c : message) {
    state = decoder.feed(std::string_view(&c, 1), out);
  }
  CHECK(state == State::Done);
  CHECK(out == "abcdef");
}

TEST_CASE("An unfinished message stays incomplete", "[chunk]")
{
  std::string out;
  CHECK(decode("5\r\nhel", out) == State::Incomplete);
  CHECK(out == "hel");
}

TEST_CASE("A bare LF after chunk data is accepted", "[chunk]")
{
  std::string out;
  CHECK(decode("5\nhello\n0\n\n", out) == State::Done);
  CHECK(out == "hello");
}

TEST_CASE("An empty body is decoded", "[chunk]")
{
  std::string out;
  CHECK(decode("0\r\n\r\n", out) == State::Done);
  CHECK(out.empty());
}

TEST_CASE("A non-hex chunk size is an error", "[chunk]")
{
  std::string out;
  CHECK(decode("z\r\nhello\r\n0\r\n\r\n", out) == State::Error);
}

TEST_CASE("Garbage after the chunk data is an error", "[chunk]")
{
  std::string out;
  CHECK(decode("5\r\nhelloXX0\r\n\r\n", out) == State::Error);
}

TEST_CASE("An oversized chunk-size line is an error", "[chunk]")
{
  std::string       out;
  std::string const huge(300, 'f');
  CHECK(decode(huge + "\r\n", out) == State::Error);
}

TEST_CASE("A terminal state is sticky", "[chunk]")
{
  ChunkDecoder decoder;
  std::string  out;
  CHECK(decoder.feed("0\r\n\r\n", out) == State::Done);
  CHECK(decoder.feed("5\r\nhello\r\n", out) == State::Done);
  CHECK(out.empty());
}
