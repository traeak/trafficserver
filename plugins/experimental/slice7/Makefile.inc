#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

pkglib_LTLIBRARIES += experimental/slice7/slice7.la

experimental_slice7_slice7_la_SOURCES = \
  experimental/slice7/client.cc \
  experimental/slice7/client.h \
  experimental/slice7/Config.cc \
  experimental/slice7/Config.h \
  experimental/slice7/ContentRange.cc \
  experimental/slice7/ContentRange.h \
  experimental/slice7/Data.cc \
  experimental/slice7/Data.h \
  experimental/slice7/HttpHeader.cc \
  experimental/slice7/HttpHeader.h \
  experimental/slice7/intercept.cc \
  experimental/slice7/intercept.h \
  experimental/slice7/Range.cc \
  experimental/slice7/Range.h \
  experimental/slice7/response.cc \
  experimental/slice7/response.h \
  experimental/slice7/server.cc \
  experimental/slice7/server.h \
  experimental/slice7/slice7.cc \
  experimental/slice7/slice7.h \
  experimental/slice7/Stage.h \
  experimental/slice7/transfer.cc \
  experimental/slice7/transfer.h

check_PROGRAMS += experimental/slice7/test_content_range

experimental_slice7_test_content_range_CPPFLAGS = $(AM_CPPFLAGS) -I$(abs_top_srcdir)/tests/include -DUNITTEST
experimental_slice7_test_content_range_SOURCES = \
  experimental/slice7/unit-tests/test_content_range.cc \
  experimental/slice7/ContentRange.cc

check_PROGRAMS += experimental/slice7/test_range

experimental_slice7_test_range_CPPFLAGS = $(AM_CPPFLAGS) -I$(abs_top_srcdir)/tests/include -DUNITTEST
experimental_slice7_test_range_SOURCES = \
  experimental/slice7/unit-tests/test_range.cc \
  experimental/slice7/Range.cc

check_PROGRAMS += experimental/slice7/test_config

experimental_slice7_test_config_CPPFLAGS = $(AM_CPPFLAGS) -I$(abs_top_srcdir)/tests/include -DUNITTEST
experimental_slice7_test_config_SOURCES = \
  experimental/slice7/unit-tests/test_config.cc \
  experimental/slice7/Config.cc
