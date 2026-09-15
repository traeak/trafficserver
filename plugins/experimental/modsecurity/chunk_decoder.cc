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

#include "chunk_decoder.h"

#include <cctype>

namespace modsecurity_plugin
{
namespace
{
  constexpr size_t MAX_SIZE_LINE = 256; // guards against an unbounded size or extension line

  bool
  hex_value(char c, size_t &value)
  {
    if (c >= '0' && c <= '9') {
      value = static_cast<size_t>(c - '0');
    } else if (c >= 'a' && c <= 'f') {
      value = static_cast<size_t>(c - 'a' + 10);
    } else if (c >= 'A' && c <= 'F') {
      value = static_cast<size_t>(c - 'A' + 10);
    } else {
      return false;
    }
    return true;
  }
} // namespace

ChunkDecoder::State
ChunkDecoder::feed(std::string_view input, std::string &out)
{
  if (_state != State::Incomplete) {
    return _state;
  }

  size_t i = 0;

  while (i < input.size()) {
    char const c = input[i];

    switch (_phase) {
    case Phase::Size: {
      if (++_size_len > MAX_SIZE_LINE) {
        return _state = State::Error;
      }
      if (c == '\n') {
        if (!_saw_size) {
          return _state = State::Error;
        }
        _last_chunk   = _remaining == 0;
        _phase        = _last_chunk ? Phase::Trailer : Phase::Data;
        _in_extension = false;
        _size_len     = 0;
        ++i;
      } else if (c == '\r') {
        // Ends the size line, the LF follows.
        ++i;
      } else if (_in_extension) {
        // Everything from a ';' to the end of the line is an ignored extension.
        ++i;
      } else if (c == ';') {
        if (!_saw_size) {
          return _state = State::Error;
        }
        _in_extension = true;
        ++i;
      } else {
        size_t digit = 0;
        if (!hex_value(c, digit)) {
          return _state = State::Error;
        }
        _remaining = _remaining * 16 + digit;
        _saw_size  = true;
        ++i;
      }
    } break;

    case Phase::Data: {
      if (_remaining == 0) {
        _phase = Phase::DataCR;
        break;
      }
      size_t const avail = input.size() - i;
      size_t const take  = avail < _remaining ? avail : _remaining;
      out.append(input.data() + i, take);
      _remaining -= take;
      i          += take;
      if (_remaining == 0) {
        _phase = Phase::DataCR;
      }
    } break;

    case Phase::DataCR: {
      // Accept CRLF or a bare LF after the chunk data.
      if (c == '\r') {
        _phase = Phase::DataLF;
        ++i;
      } else if (c == '\n') {
        _phase    = Phase::Size;
        _saw_size = false;
        _size_len = 0;
        ++i;
      } else {
        return _state = State::Error;
      }
    } break;

    case Phase::DataLF: {
      if (c != '\n') {
        return _state = State::Error;
      }
      _phase    = Phase::Size;
      _saw_size = false;
      _size_len = 0;
      ++i;
    } break;

    case Phase::Trailer: {
      // A bare LF (or CRLF) with no trailer content ends the message.
      if (c == '\n') {
        return _state = State::Done;
      } else if (c == '\r') {
        _phase = Phase::TrailerCR;
        ++i;
      } else {
        // A trailer line: consume up to and including its LF.
        ++i;
      }
    } break;

    case Phase::TrailerCR: {
      if (c != '\n') {
        return _state = State::Error;
      }
      return _state = State::Done;
    } break;
    }
  }

  return _state;
}
} // namespace modsecurity_plugin
