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

#include <cstddef>
#include <string>
#include <string_view>

namespace modsecurity_plugin
{
// Decodes an HTTP/1.1 chunked message body incrementally. Traffic Server buffers
// a chunked request body with its chunk framing intact, so the framing is
// stripped here before the body is handed to ModSecurity. Bytes are fed in
// whatever sizes they arrive in; the decoded content is appended to "out".
class ChunkDecoder
{
public:
  enum class State {
    Incomplete, // more input is expected
    Done,       // the terminating zero-length chunk was seen
    Error,      // the input is not valid chunked encoding
  };

  // Consume "input", appending any decoded body bytes to "out". Returns the
  // state after this input. Once Done or Error is returned, further input keeps
  // returning the same state without appending.
  State feed(std::string_view input, std::string &out);

  State
  state() const
  {
    return _state;
  }

private:
  enum class Phase {
    Size,      // reading the hex chunk-size line
    Data,      // reading chunk-data bytes
    DataCR,    // expecting the CR after chunk-data
    DataLF,    // expecting the LF after chunk-data
    Trailer,   // reading trailer lines after the last chunk
    TrailerCR, // expecting the LF that ends a trailer line
  };

  State  _state        = State::Incomplete;
  Phase  _phase        = Phase::Size;
  size_t _remaining    = 0;     // bytes left in the current chunk
  bool   _saw_size     = false; // at least one hex digit seen for this size
  bool   _last_chunk   = false; // the current size line was a zero
  bool   _in_extension = false; // past the ';' that starts chunk extensions
  size_t _size_len     = 0;     // length of the current size line, for a bound
};
} // namespace modsecurity_plugin
