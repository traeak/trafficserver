.. _admin-plugins-modsecurity:

ModSecurity Plugin
******************

.. Licensed to the Apache Software Foundation (ASF) under one
   or more contributor license agreements.  See the NOTICE file
   distributed with this work for additional information
   regarding copyright ownership.  The ASF licenses this file
   to you under the Apache License, Version 2.0 (the
   "License"); you may not use this file except in compliance
   with the License.  You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing,
   software distributed under the License is distributed on an
   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
   KIND, either express or implied.  See the License for the
   specific language governing permissions and limitations
   under the License.

.. include:: ../../common.defs

This plugin turns |TS| into a web application firewall by handing transactions
to `ModSecurity v3 <https://github.com/owasp-modsecurity/ModSecurity>`_
(``libmodsecurity``). ModSecurity evaluates its rules and may ask the plugin to
block the request, or to redirect the client somewhere else.

It can be loaded either as a global plugin, in which case it inspects every
transaction, or as a remap plugin, in which case it inspects only the
transactions matching that remap rule. Each instance has its own set of rule
files.

Building
========

``libmodsecurity`` and its development headers must be installed. The plugin is
built along with the other experimental plugins::

   cmake -B build -DBUILD_EXPERIMENTAL_PLUGINS=ON
   cmake --build build

Passing ``-DENABLE_MODSECURITY=ON`` makes a missing ``libmodsecurity`` a configure
error instead of quietly skipping the plugin.

Configuration
=============

As a global plugin, add it to :file:`plugin.config` followed by one or more
ModSecurity rule files. Files are loaded in the order given::

   modsecurity.so modsecurity/example.conf

As a remap plugin, the rule files are passed as ``pparam`` arguments::

   map http://example.com/ http://origin/ @plugin=modsecurity.so @pparam=modsecurity/example.conf

A relative path is resolved against the |TS| configuration directory.
``Include`` directives inside a rule file are resolved relative to the
including file, which is how the OWASP Core Rule Set is normally pulled in.

If no rule file can be parsed at startup the plugin logs an error and inspects
no traffic. |TS| itself still starts and proxies normally.

Reloading rules
===============

The rules of the global instance are reloaded on demand with
:program:`traffic_ctl`::

   traffic_ctl plugin msg modsecurity reload

The rule files named in :file:`plugin.config` are re-read into a new rule set.
If any of them fails to parse, the error is logged and the previously loaded
rules stay in effect. Transactions that are already in flight finish against
the rule set they started with.

Note that ``traffic_ctl config reload`` does *not* reload the rules of the
global instance. It does recreate every remap instance, so remap instances pick
up their rule changes that way.

What is inspected
=================

The plugin runs the ModSecurity phases that do not need a message body:

==================================  ==============================================
|TS| hook                           ModSecurity processing
==================================  ==============================================
``TS_HTTP_READ_REQUEST_HDR_HOOK``   connection, URI, request headers (phases 1, 2)
``TS_HTTP_READ_RESPONSE_HDR_HOOK``  response headers (phases 3, 4)
``TS_HTTP_SEND_RESPONSE_HDR_HOOK``  adds the ``Location`` header of a redirect
``TS_HTTP_TXN_CLOSE_HOOK``          ModSecurity logging and cleanup
==================================  ==============================================

A remap instance runs the request phases from ``TSRemapDoRemap`` instead of
``TS_HTTP_READ_REQUEST_HDR_HOOK``, and therefore sees the URL as rewritten by
its remap rule rather than the URL the client sent. The remaining hooks are the
same.

The client address and port are taken from the client connection, and the
server address and port from the |TS| port the request arrived on, so rules on
``REMOTE_ADDR``, ``REMOTE_PORT``, ``SERVER_ADDR`` and ``SERVER_PORT`` work as
expected.

Interventions
=============

When ModSecurity asks for an intervention:

- A status other than 200 aborts the transaction and |TS| returns that status
  with a short ``text/plain`` body. Interventions on the response side replace
  the origin response.
- A ``redirect`` action additionally sets the ``Location`` header on the
  response sent to the client.

Macros in a ``redirect`` target expand to *decoded* request data, so a rule
such as ``redirect:'https://blocked.example.com/?u=%{REQUEST_URI}'`` puts bytes
the client chose into a response header. The plugin discards any redirect
target containing a control character and logs an error, so that a request
carrying ``%0d%0a`` cannot inject headers into the response. The transaction is
still blocked by the intervention status; only the ``Location`` header is
dropped. Prefer static redirect targets regardless.

Logging
=======

Messages produced by rules with a ``log`` action are written to
:file:`diags.log` at the ``NOTE`` level, tagged with ``modsecurity``. ModSecurity's own
debug and audit logs are configured in the rule file with ``SecDebugLog`` and
``SecAuditLog``.

Debug output from the plugin is enabled with the ``modsecurity`` debug tag::

   proxy.config.diags.debug.enabled: 1
   proxy.config.diags.debug.tags: modsecurity

Limitations
===========

- ``REQUEST_BODY`` is not inspected. Doing so would require buffering the
  entire request body before it could be sent to the origin.
- ``RESPONSE_BODY`` is not inspected. The body would have to be decompressed
  first, which is expensive in a proxy. See
  `ModSecurity issue 2494 <https://github.com/SpiderLabs/ModSecurity/issues/2494>`_.
- The response phases run on origin responses only. A response served out of
  the cache never reaches ``TS_HTTP_READ_RESPONSE_HDR_HOOK``, so phase 3 and 4
  rules do not see it. Request phase rules run on every transaction.

Rules that depend on either body can never match. When running the OWASP Core
Rule Set they are best disabled with ``SecRuleRemoveById`` so that they are not
evaluated at all.
