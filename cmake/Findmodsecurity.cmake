#######################
#
#  Licensed to the Apache Software Foundation (ASF) under one or more contributor license
#  agreements.  See the NOTICE file distributed with this work for additional information regarding
#  copyright ownership.  The ASF licenses this file to you under the Apache License, Version 2.0
#  (the "License"); you may not use this file except in compliance with the License.  You may obtain
#  a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
#  or implied. See the License for the specific language governing permissions and limitations under
#  the License.
#
#######################

# Findmodsecurity.cmake
#
# This will define the following variables
#
#     modsecurity_FOUND
#     modsecurity_LIBRARY
#     modsecurity_INCLUDE_DIRS
#
# and the following imported targets
#
#     modsecurity::modsecurity
#

# libmodsecurity ships a pkg-config file but no CMake package config. The
# pkg-config result is only used as a hint since the library is frequently
# installed into a prefix of its own, e.g. /usr/local/modsecurity.
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(PC_modsecurity QUIET modsecurity)
endif()

find_library(
  modsecurity_LIBRARY
  NAMES modsecurity
  HINTS ${PC_modsecurity_LIBRARY_DIRS}
  PATH_SUFFIXES modsecurity/lib
)
find_path(
  modsecurity_INCLUDE_DIR
  NAMES modsecurity/modsecurity.h
  HINTS ${PC_modsecurity_INCLUDE_DIRS}
  PATH_SUFFIXES modsecurity/include
)

mark_as_advanced(modsecurity_FOUND modsecurity_LIBRARY modsecurity_INCLUDE_DIR)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(modsecurity REQUIRED_VARS modsecurity_LIBRARY modsecurity_INCLUDE_DIR)

if(modsecurity_FOUND)
  set(modsecurity_INCLUDE_DIRS ${modsecurity_INCLUDE_DIR})
endif()

if(modsecurity_FOUND AND NOT TARGET modsecurity::modsecurity)
  add_library(modsecurity::modsecurity INTERFACE IMPORTED)
  target_include_directories(modsecurity::modsecurity INTERFACE ${modsecurity_INCLUDE_DIRS})
  target_link_libraries(modsecurity::modsecurity INTERFACE "${modsecurity_LIBRARY}")
endif()
