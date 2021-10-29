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

.. _admin-plugins-revalidate:

Revalidate Plugin
*****************

This plugin allows for the creation of rules which match regular expressions
against mapped URLs to determine if and when a cache object revalidation should
be forced.

Purpose
=======

This plugin's intended use is the selective forcing of revalidations on cache
objects which are not yet marked as stale in |TS| but which may have been
updated at the origin - without needing to alter cache control headers,
preemptively purge the object from the cache manually, or adjust the global
cache revalidation settings (such as fuzz times) used by other plugins.

Forced cache revalidations may be as specifically or loosely targeted as a
regular expression against your origin URLs permits. Thus, individual cache
objects may have rules created for them, or entire path prefixes, or even any
cache objects with a particular file extension.

Revalidate count stats for MISS and STALE are recorded under:

* plugin.revalidate.stale
* plugin.revalidate.miss

Installation
============

To make this plugin available, you must enable experimental plugins when
building |TS|::

    ./configure --enable-experimental-plugins

Configuration
=============

This plugin is enabled via the :file:`plugin.config` configuration file, with
required argument to the rule configuration file::

    revalidate.so --rule-path=<path to rules>

The rule configuration file format is described below in `Revalidation Rules`_.

The rules file is checked for changes under the following conditions:

* ``traffic_ctl config reload``
* ``traffic_ctl plugin msg revalidate reload``

If the file has been modified since its last scan, the contents are read
and the in-memory rules list is updated.  Only rules listed in the file
are loaded.

Options::

* --rule_path=<path to rules> (-r): List of rules.
* --header=<header name> (-h): Propagation header name override.
* --log-path=<path to log> (-l): Log of loaded rules.

It is advisable to either use a custom header rule name or remove
the `X-Revalidate-Rule` header at the incoming edge tier.

Revalidation Rules
==================

Inside your revalidation rules configuration, each rule line is defined as a
regular expression followed by an integer which expresses the epoch time at
which the rule will expire::

    <regular expression> <rule expiry, as seconds since epoch> <MISS or STALE>

Blank lines and lines beginning with a ``#`` character are ignored.

Matching Expression
-------------------

PCRE style regular expressions are supported and should be used to match
against the complete remapped URL of cache objects (not the original
client-side URL), including protocol scheme and origin server domain.
Care must be taken to ensure that rules are simple and are not malicious.

Rule Expiration
---------------

Every rule must have an expiration associated with it. The rule expiration is
expressed as an integer of seconds since epoch (equivalent to the return value
of :manpage:`time(2)`), after which the forced revalidation will no longer
occur.

Rule Type
---------

Valid values are:

* STALE
* MISS

By default any matching asset will have its cache lookup status changed
from HIT_FRESH to either HIT_STALE or HIT_MISS depending on this setting.

STALE should always be the preferred type.  MISS should only be used if
the origin is known to be defective and not properly handle IMS requests.
MISS will force a refetch from the parent. *Use with care* as this will
increase bandwidth to the parent.  During configuration reload, any rule
which changes it type will be reloaded and treated as a new rule.

Rule Propagation
----------------

The previous `regex_revalidate` plugin only managed revalidate rules
for the current running instance of `ATS`. That plugin requires rule
sets to be be fully loaded in tier order from origin facing down to
client facing.

This plugin adds rule propagation. During the `cache lookup complete`
hook the following happens:

* Client request is checked for the `X-Revalidate-Rule` header.
** If valid rule, merge with the current loaded rule set.
*** Expired rule can be used to erase an existing rule.
* If request is cache hit:
** Check against the merged new rule for STALE/MISS.
** If necessary, continue checking the remaining rules.
* If request is cache miss:
** Check for existing matching rule.
* If any matching applicable rule, (re)set the upstream header.

Caveats
=======

Matches Only Post-Remapping
---------------------------

The regular expressions in revalidation rules see only the final, remapped URL
in a transaction. As such, they cannot be used to distinguish between two
client-facing URLs which are mapped to the same origin object. This is due to
the fact that the plugin uses :c:data:`TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK`.

Removing Rules
--------------

While new rules are added dynamically (the configuration file is checked every
60 seconds for changes), rule lines removed from the configuration file do not
currently lead to that rule being removed from the running plugin. In these
cases, if the rule must be taken out of service, a service restart may be
necessary.

State File
----------

The state file is not meant to be edited but is of the format::

<regular expression> <rule epoch> <rule expiry> <type>


Examples
========

The following rule would cause the cache object whose origin server is
``origin.tld`` and whose path is ``/images/foo.jpg`` to be revalidated by force
in |TS| until 6:47:27 AM on Saturday, November 14th, 2015 (UTC)::

    http://origin\.tld/images/foo\.jpg 1447483647

Note the escaping of the ``.`` metacharacter in the rule's regular expression.

Alternatively the following rule would case a refetch from the parent::

    http://origin\.tld/images/foo\.jpg 1447483647 MISS
