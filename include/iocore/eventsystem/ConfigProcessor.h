/** @file

  A brief file description

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

#include <atomic>

#include "iocore/eventsystem/EventProcessor.h"
#include "iocore/eventsystem/Tasks.h"
#include "records/RecCore.h"

class ProxyMutex;

#define MAX_CONFIGS 100

using ConfigInfo = RefCountObjInHeap;

class ConfigProcessor
{
public:
  ConfigProcessor() = default;

  enum {
    // The number of seconds to wait before garbage collecting stale ConfigInfo objects. There's
    // no good reason to tune this, outside of regression tests, so don't.
    CONFIG_PROCESSOR_RELEASE_SECS = 60
  };

  template <typename ClassType, typename ConfigType> struct scoped_config {
    scoped_config() : ptr(ClassType::acquire()) {}
    ~scoped_config() { ClassType::release(ptr); }
    operator bool() const { return ptr != nullptr; }
    operator const ConfigType *() const { return ptr; }
    const ConfigType *
    operator->() const
    {
      return ptr;
    }

  private:
    ConfigType *ptr;
  };

  unsigned int set(unsigned int id, ConfigInfo *info, unsigned timeout_secs = CONFIG_PROCESSOR_RELEASE_SECS);
  ConfigInfo  *get(unsigned int id);
  void         release(unsigned int id, ConfigInfo *data);

public:
  std::atomic<ConfigInfo *> infos[MAX_CONFIGS] = {nullptr};
  std::atomic<int>          ninfos{0};
};

// A Continuation wrapper that calls the static reconfigure() method of the given class.
template <typename UpdateClass> struct ConfigUpdateContinuation : public Continuation {
  int
  update(int /* etype */, void * /* data */)
  {
    UpdateClass::reconfigure();
    delete this;
    return EVENT_DONE;
  }

  ConfigUpdateContinuation(Ptr<ProxyMutex> &m) : Continuation(m.get()) { SET_HANDLER(&ConfigUpdateContinuation::update); }
};

template <typename UpdateClass>
int
ConfigScheduleUpdate(Ptr<ProxyMutex> &mutex)
{
  eventProcessor.schedule_imm(new ConfigUpdateContinuation<UpdateClass>(mutex), ET_TASK);
  return 0;
}

template <typename UpdateClass> struct ConfigUpdateHandler {
  ConfigUpdateHandler() : mutex(new_ProxyMutex()) {}
  // The mutex member is ref-counted so should not explicitly free it
  ~ConfigUpdateHandler() {}
  int
  attach(const char *name)
  {
    return RecRegisterConfigUpdateCb(name, ConfigUpdateHandler::update, this);
  }

private:
  static int
  update(const char *name, RecDataT /* data_type ATS_UNUSED */, RecData /* data ATS_UNUSED */, void *cookie)
  {
    ConfigUpdateHandler *self = static_cast<ConfigUpdateHandler *>(cookie);

    Dbg(_dbg_ctl, "%s(%s)", __PRETTY_FUNCTION__, name);
    return ConfigScheduleUpdate<UpdateClass>(self->mutex);
  }

  Ptr<ProxyMutex> mutex;

  inline static DbgCtl _dbg_ctl{"config"};
};

extern ConfigProcessor configProcessor;
