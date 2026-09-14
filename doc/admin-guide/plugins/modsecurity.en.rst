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

Choose one mode for a given transaction. If the plugin is loaded as a global
plugin *and* on a remap rule, a transaction matching that rule is inspected by
both instances, each against its own rule files, unless the global plugin has
already blocked it.

Building
========

``libmodsecurity`` and its development headers must be installed. The plugin is
built along with the other experimental plugins::

   cmake -B build -DBUILD_EXPERIMENTAL_PLUGINS=ON
   cmake --build build

Passing ``-DENABLE_MODSECURITY=ON`` makes a missing ``libmodsecurity`` a
configure error instead of quietly skipping the plugin.

Configuration
=============

Global plugin
-------------

Add the plugin to :file:`plugin.config`, followed by one or more ModSecurity
rule files::

   modsecurity.so modsecurity/example.conf

Remap plugin
------------

Add the plugin to a remap rule, passing each rule file as a ``pparam``::

   map http://example.com/ http://origin/ @plugin=modsecurity.so @pparam=modsecurity/example.conf

Rule files
----------

In both modes the rule files are loaded in the order given, and a relative path
is resolved against the |TS| configuration directory. ``Include`` directives
inside a rule file are resolved relative to the including file, which is how
the OWASP Core Rule Set is normally pulled in.

Loading and reloading rules
===========================

The two modes load their rules at different times, and fail in opposite ways
when a rule file cannot be parsed.

Global plugin
-------------

The rule files named in :file:`plugin.config` are loaded at startup. If any of
them fails to parse, the plugin logs an error and inspects no traffic: |TS|
still starts, and proxies every transaction uninspected until the rule files
are fixed and reloaded.

The rule files are registered with the |TS| configuration reload framework, so
``traffic_ctl config reload`` reloads the rules whenever one of the files has
changed. The reload shows up as the ``modsecurity`` task in
``traffic_ctl config status``. If a rule file fails to parse, that task fails
with the parse error, and the previously loaded rules stay in effect.

To reload the rules whether or not a file has changed, send the plugin a
message::

   traffic_ctl plugin msg modsecurity reload

This form always reports success, so check :file:`error.log` after using it.

Remap plugin
------------

The rule files of a remap instance are loaded along with :file:`remap.config`.
Each rule file is attached to the remap configuration file in use,
:file:`remap.yaml` if it exists and :file:`remap.config` otherwise, so
``traffic_ctl config reload`` reloads that file, and with it every remap
instance, whenever one of the rule files has changed. The ``plugin msg`` reload
does not apply to remap instances.

A rule file that fails to parse fails the whole :file:`remap.config` load, not
only the remap rule that uses the plugin:

- At startup, |TS| does not start.
- On ``traffic_ctl config reload``, the reload of :file:`remap.config` is
  rejected and the previous remap configuration, including the previous rules,
  stays in effect. Every other change made to :file:`remap.config` in the same
  reload is rejected along with it.

Both modes
----------

Only the rule files named in the configuration are watched for changes. Files
pulled in with ``Include``, such as the ``rules/*.conf`` files of the OWASP Core
Rule Set, are not. After changing one of those, update the modification time of
a named rule file, for example with :program:`touch`, before running
``traffic_ctl config reload``.

Transactions that are already in flight finish against the rule set they
started with.

What is inspected
=================

.. warning::

   Response phase rules (phases 3 and 4) run only on responses fetched from the
   origin. A response served from the cache never reaches
   ``TS_HTTP_READ_RESPONSE_HDR_HOOK``, so on a cache hit the response rules do
   not run at all, and nothing records that they were skipped. On a proxy that
   serves most requests from its cache, most responses are never inspected by
   these rules. Request phase rules run on every transaction, in both modes.

The plugin runs the ModSecurity phases that do not need a message body. As a
global plugin it uses these hooks:

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

In both modes the client address and port are taken from the client
connection, and the server address and port from the |TS| port the request
arrived on, so rules on ``REMOTE_ADDR``, ``REMOTE_PORT``, ``SERVER_ADDR`` and
``SERVER_PORT`` work as expected.

Interventions
=============

In both modes, when ModSecurity asks for an intervention:

- A status other than 200 aborts the transaction and |TS| returns that status
  with a short ``text/plain`` body. Interventions on the response side replace
  the origin response.
- A ``redirect`` action additionally sets the ``Location`` header on the
  response sent to the client. A redirect that does not set a status, or sets
  it to 200, responds with 302.

Macros in a ``redirect`` target expand to *decoded* request data, so a rule
such as ``redirect:'https://blocked.example.com/?u=%{REQUEST_URI}'`` puts bytes
the client chose into a response header. The plugin discards any redirect
target containing a control character and logs a warning, so that a request
carrying ``%0d%0a`` cannot inject headers into the response. The transaction is
still blocked by the intervention status; only the ``Location`` header is
dropped. Prefer static redirect targets regardless.

Statistics
==========

The plugin counts the transactions it blocks: every intervention that carries
a status other than 200 or a redirect.

``proxy.process.plugin.modsecurity.interventions.request``
   Transactions blocked by the request phase rules (phases 1 and 2). These
   never reach the origin.

``proxy.process.plugin.modsecurity.interventions.response``
   Transactions blocked by the response phase rules (phases 3 and 4). The
   origin response is replaced.

``proxy.process.plugin.modsecurity.redirects_dropped``
   Redirect targets discarded because they contained a control character, as
   described under Interventions.

The counters are process wide. The global plugin and every remap instance
update the same counters, so they do not tell the two modes apart. They reset
when |TS| restarts. Read one with :program:`traffic_ctl`::

   traffic_ctl metric get proxy.process.plugin.modsecurity.interventions.request

Logging
=======

In both modes, messages produced by rules with a ``log`` action are written to
:file:`diags.log` at the ``NOTE`` level, tagged with ``modsecurity``.
ModSecurity's own debug and audit logs are configured in the rule file with
``SecDebugLog`` and ``SecAuditLog``.

Debug output from the plugin is enabled with the ``modsecurity`` debug tag::

   proxy.config.diags.debug.enabled: 1
   proxy.config.diags.debug.tags: modsecurity

Limitations
===========

These apply to both modes.

- ``REQUEST_BODY`` is not inspected. Doing so would require buffering the
  entire request body before it could be sent to the origin.
- ``RESPONSE_BODY`` is not inspected. The body would have to be decompressed
  first, which is expensive in a proxy. See
  `ModSecurity issue 2494 <https://github.com/SpiderLabs/ModSecurity/issues/2494>`_.
- Response phase rules do not run on cache hits. See the warning under
  What is inspected.

Rules that depend on either body can never match. When running the OWASP Core
Rule Set they are best disabled with ``SecRuleRemoveById`` so that they are not
evaluated at all.
