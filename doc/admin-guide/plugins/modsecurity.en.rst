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

The two modes can also run together, with a system-wide baseline in the global
plugin and endpoint-specific rules on remap rules. See Using both modes.

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

libmodsecurity does not support ``IncludeOptional``, and an ``Include`` whose
pattern matches no file fails the load, like any other error in a rule file.

Basic setup with the OWASP Core Rule Set
----------------------------------------

`coreruleset.org <https://coreruleset.org>`_ publishes the OWASP Core Rule Set,
up to date generic attack detection rules for ModSecurity. It runs on top of a
ModSecurity base configuration made from two files in the
`ModSecurity repository <https://github.com/owasp-modsecurity/ModSecurity>`_:
``modsecurity.conf-recommended`` and ``unicode.mapping``.

The steps below build this layout under the |TS| configuration directory::

   modsecurity/
     crs.conf              the file the plugin loads
     modsecurity.conf      from ModSecurity's modsecurity.conf-recommended
     unicode.mapping       from ModSecurity's unicode.mapping
     crs/                  the Core Rule Set release
       crs-setup.conf      from crs-setup.conf.example
       plugins/
       rules/

#. Download a Core Rule Set release from `coreruleset.org
   <https://coreruleset.org>`_ and extract it. Move or link the extracted
   directory to ``modsecurity/crs``, and copy ``crs/crs-setup.conf.example`` to
   ``crs/crs-setup.conf``.

#. Fetch the two ModSecurity files from the release tag that matches the
   installed libmodsecurity, ``v3.0.14`` for libmodsecurity 3.0.14, so that the
   base configuration only uses directives that version understands::

      cd modsecurity
      curl -L -o modsecurity.conf https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3.0.14/modsecurity.conf-recommended
      curl -L -O https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3.0.14/unicode.mapping

#. Edit ``modsecurity.conf``:

   - Set ``SecRuleEngine On``. The recommended file sets ``DetectionOnly``,
     which only logs: nothing is blocked.
   - Point ``SecAuditLog`` at a file the |TS| user can write, or set
     ``SecAuditEngine Off``. The default, ``/var/log/modsec_audit.log``, is
     usually not writable by that user, and the rules load regardless, so
     nothing reports the problem at startup.

   Leave ``unicode.mapping`` next to ``modsecurity.conf`` under that name.
   ``SecUnicodeMapFile unicode.mapping 20127`` refers to it, and a missing file
   fails the whole load, so a copy named ``unicode.mapping.dist`` must be
   renamed.

#. Copy ``owasp.conf`` from the plugin's source directory to
   ``modsecurity/crs.conf``. It includes the files in the order the Core Rule
   Set expects::

      Include "modsecurity.conf"
      Include "crs/crs-setup.conf"
      Include "crs/plugins/*-config.conf"
      Include "crs/plugins/*-before.conf"
      Include "crs/rules/*.conf"
      Include "crs/plugins/*-after.conf"

#. Load it as a global plugin, a remap plugin, or both, and restart |TS|::

      # plugin.config
      modsecurity.so modsecurity/crs.conf

      # remap.config
      map http://example.com/ http://origin/ @plugin=modsecurity.so @pparam=modsecurity/crs.conf

#. Check that attacks are blocked. A request carrying a scanner's user agent is
   answered with a 403, and the block is recorded in the audit log. With |TS|
   listening on its default port, 8080::

      curl -o /dev/null -w '%{http_code}\n' -H 'Host: example.com' -H 'User-Agent: Nikto' http://127.0.0.1:8080/

The request and response body settings in ``modsecurity.conf`` have no effect,
because the plugin never passes bodies to ModSecurity.

The Core Rule Set's own installation guide includes its plugin files with
``IncludeOptional``, which libmodsecurity does not support, hence the plain
``Include`` lines in ``crs.conf``. Because a pattern that matches no file fails
the load, keep the empty ``*-config.conf``, ``*-before.conf`` and
``*-after.conf`` files that ship in ``plugins/``, or drop the corresponding
lines.

With libmodsecurity 3.0.14 and Core Rule Set 4.29.0, this setup loads 847 rules.

Using both modes
================

The global plugin and remap instances can run together. This lets one set of
rules protect everything the proxy serves, while endpoints that need more get
their own rules on top, without repeating the baseline for each of them. Load
the system-wide baseline globally, such as the OWASP Core Rule Set, and add the
rules that only concern particular endpoints on the remap rules for those
endpoints::

   # plugin.config
   modsecurity.so modsecurity/baseline.conf

   # remap.config
   map http://api.example.com/ http://origin/ @plugin=modsecurity.so @pparam=modsecurity/api.conf

A transaction that matches such a remap rule is inspected by both instances,
each running its own ModSecurity transaction against its own rule set. The
global plugin inspects the request first, against the URL the client sent. The
remap instance only runs if the global plugin has not blocked the request, and
it sees the URL as rewritten by its remap rule. Both instances inspect the
response.

Whichever instance blocks the transaction first decides the response. The other
instance leaves that response alone: it neither runs its response rules on it
nor counts it in the statistics. Each instance logs the rules that matched in
its own transaction.

Keep in mind:

- A remap instance can only add to what the global plugin enforces. Directives
  in its rule files, ``SecRuleRemoveById`` included, affect only its own rule
  set, so they cannot exempt an endpoint from a rule the global plugin loads. To
  exempt some endpoints from a rule, load that rule through the remap rules of
  the other endpoints rather than globally.
- Every matching transaction is evaluated against both rule sets. Keep the
  remap rule files to what is specific to the endpoint: repeating the baseline
  there would evaluate it twice.
- Each instance loads and reloads its rule files on its own, as described in
  the next section.

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

The plugin runs the ModSecurity phases that do not need a message body. As a
global plugin it uses these hooks:

========================================  =================================================
|TS| hook                                 ModSecurity processing
========================================  =================================================
``TS_HTTP_READ_REQUEST_HDR_HOOK``         connection, URI, request headers (phase 1)
``TS_HTTP_REQUEST_BUFFER_READ_COMPLETE``  request body, then phase 2 (only when enabled)
``TS_HTTP_READ_RESPONSE_HDR_HOOK``        headers of an origin response (phases 3, 4)
``TS_HTTP_SEND_RESPONSE_HDR_HOOK``        headers of any other response (phases 3, 4)
``TS_HTTP_TXN_CLOSE_HOOK``                ModSecurity logging and cleanup
========================================  =================================================

Response phase rules run on every response. A response fetched from the origin
is inspected as soon as its headers arrive, so a response the rules block is
never written to the cache. Any other response, such as one served from the
cache or an error response generated by |TS|, is inspected just before it is
sent, using the headers |TS| is about to send. Those can include headers |TS|
adds itself, such as ``Age``, so a rule may see slightly different headers on a
cache hit than on an origin fetch. This adds response inspection to every cache
hit. ``TS_HTTP_SEND_RESPONSE_HDR_HOOK`` also puts the status and the
``Location`` header of an intervention in place.

A remap instance runs the request phases from ``TSRemapDoRemap`` instead of
``TS_HTTP_READ_REQUEST_HDR_HOOK``, and therefore sees the URL as rewritten by
its remap rule rather than the URL the client sent. The remaining hooks are the
same.

In both modes the client address and port are taken from the client
connection, and the server address and port from the |TS| port the request
arrived on, so rules on ``REMOTE_ADDR``, ``REMOTE_PORT``, ``SERVER_ADDR`` and
``SERVER_PORT`` work as expected.

Request body inspection
=======================

By default the request body is not inspected, and the phase 2 rules run against
the headers alone. Pass the ``--inspect-request-body`` argument, in
:file:`plugin.config` or as a ``@pparam``, to inspect it::

   modsecurity.so --inspect-request-body modsecurity/example.conf

With it, a request that has a body is held until the whole body has arrived,
then the body is handed to ModSecurity and the phase 2 rules run against it,
before the origin is contacted. This is what the ``REQUEST_BODY`` variable and
the Core Rule Set's request body rules need. A blocked request never reaches the
origin. The body is inspected in both modes, and for both a plain and a chunked
body.

It requires and affects the following:

- ``SecRequestBodyAccess On`` must be set in the rules, or ModSecurity ignores
  the body. The recommended ModSecurity configuration sets it.
- ``proxy.config.http.post_copy_size`` must be non-zero; it is the largest body
  |TS| buffers, and it bounds the body the plugin can inspect. A request whose
  body exceeds it fails. Raising it together with
  ``proxy.config.http.max_post_size`` lets an over-large body with a known
  length be rejected up front with a 413 rather than failing mid-body. If
  ``post_copy_size`` is zero the plugin logs an error and inspects no bodies.
- Buffering holds each such request in memory until its body is complete, and
  the origin is not contacted until then, so the upload no longer streams. Turn
  the option on only where request body inspection is worth that cost.

Interventions
=============

In both modes, when ModSecurity reports a disruptive intervention, such as one
from ``deny``, ``drop`` or ``redirect``:

- The transaction is aborted and |TS| returns the intervention's status with a
  short ``text/plain`` body. Interventions on the response side replace the
  origin response. An intervention without a status of 300 or above responds
  with 403, or with 302 for a redirect.
- A ``redirect`` action additionally sets the ``Location`` header on the
  response sent to the client.
- A response that was not fetched from the origin, such as a cache hit, cannot
  be redirected: at that point |TS| can only abort it with a status of 400 or
  above. An intervention on such a response with a lower status, which includes
  every redirect, responds with 403 instead, and nothing from the cached
  response is sent.

Rules whose actions do not disrupt, such as ``pass`` and ``allow``, never block
a transaction, and neither does any rule while ``SecRuleEngine`` is set to
``DetectionOnly``. Those only log.

Macros in a ``redirect`` target expand to *decoded* request data, so a rule
such as ``redirect:'https://blocked.example.com/?u=%{REQUEST_URI}'`` puts bytes
the client chose into a response header. The plugin discards any redirect
target containing a control character and logs a warning, so that a request
carrying ``%0d%0a`` cannot inject headers into the response. The transaction is
still blocked by the intervention status; only the ``Location`` header is
dropped. Prefer static redirect targets regardless.

Statistics
==========

The plugin counts the transactions it blocks: every disruptive intervention.

``proxy.process.plugin.modsecurity.interventions.request``
   Transactions blocked by the request phase rules (phases 1 and 2). These
   never reach the origin.

``proxy.process.plugin.modsecurity.interventions.response``
   Transactions blocked by the response phase rules (phases 3 and 4), whether
   the response came from the origin or from the cache. The response is
   replaced.

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

- ``REQUEST_BODY`` is inspected only when ``--inspect-request-body`` is set; see
  Request body inspection for the requirements and cost. Without it, rules on
  the request body cannot match.
- ``RESPONSE_BODY`` is not inspected. The body would have to be decompressed
  first, which is expensive in a proxy. See
  `ModSecurity issue 2494 <https://github.com/SpiderLabs/ModSecurity/issues/2494>`_.
- The ``pause`` action is not supported. libmodsecurity 3.0.14 refuses to load
  a rule file that uses it, which then fails like any other rule file that does
  not parse. Should a later version accept it, the plugin logs a warning once
  and ignores the pause.

Rules that depend on the response body can never match, and request body rules
match only with ``--inspect-request-body``. Rules that cannot match under the
chosen configuration are best disabled with ``SecRuleRemoveById`` so that they
are not evaluated at all.
