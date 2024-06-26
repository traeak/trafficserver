.. Licensed to the Apache Software Foundation (ASF) under one or more
   contributor license agreements.  See the NOTICE file distributed
   with this work for additional information regarding copyright
   ownership.  The ASF licenses this file to you under the Apache
   License, Version 2.0 (the "License"); you may not use this file
   except in compliance with the License.  You may obtain a copy of
   the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
   implied.  See the License for the specific language governing
   permissions and limitations under the License.

.. include:: ../../../common.defs

.. default-domain:: cpp

TSHttpTxnReenable
*****************

Notifies the HTTP transaction txnp that the plugin is finished
processing the current hook.

Synopsis
========

.. code-block:: cpp

    #include <ts/ts.h>

.. function:: void TSHttpTxnReenable(TSHttpTxn txnp, TSEvent event)

Description
===========

The plugin tells the transaction :arg:`txnp` to either continue
(:enumerator:`TS_EVENT_HTTP_CONTINUE`) or stop (:enumerator:`TS_EVENT_HTTP_ERROR`).

.. important::

   You must always re-enable the HTTP transaction after the processing of
   each transaction event.  However, never re-enable twice.  Reenabling
   twice is a serious error.
