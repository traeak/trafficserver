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

Revalidate count stats for STALE are recorded under:

* plugin.revalidate.count

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

* --header=<header name> (-h): Propagation header name override.
* --key_path=<path to keys> (-k): Path to public keys for rule signature check.
* --log-path=<path to log> (-l): Log of loaded rules.
* --rule_path=<path to rules> (-r): List of rules.

It is advisable to either use a custom header rule name or remove
the `X-Revalidate-Rule` header at the incoming edge tier.

Revalidation Rules
==================

Inside your revalidation rules configuration, each rule line is defined as a
regular expression followed by an integer which expresses the epoch time at
which the rule will expire::

    <regex> <rule expiry> <rule version> [signature]

Explanation of the fields::

* ``<regex>``: A PCRE style regular expression which will be matched against
  the remapped URL of cache objects.
* ``<rule expiry>``: Seconds since epoch at which the rule will expire.
* ``<rule version>``: Rule version, typically UTC creationg time.
* ``[signature]``: Optional signature of the rule.

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

Rule Version
------------

The rule version is used to determine if the rule has been updated. If the
version of an incoming rule is less than the current rule version,
the rule is considered expired.  This is useful for rule propagation.
Rule creation time should be used as the version.

Rule Propagation
----------------

The previous `regex_revalidate` plugin only managed revalidate rules
for the current running instance of `ATS`. That plugin requires rule
sets to be be fully loaded in tier order from origin facing down to
client facing.

This plugin adds rule propagation. During the `cache lookup complete`
hook the following happens:

Resolve and Merge Rules if Applicable:
* Client request is checked for the `X-Revalidate-Rule` header.
 ** Verify rule signature if applicable.
 ** If valid rule, merge with the current loaded rule set.
 ** Expired rule can be used to erase an existing rule.

Process current transaction:
* If request is cache hit, look for matching rules.
  ** First check against the merged new rule.
  ** If necessary, continue checking the remaining rules.
* Mark as STALE for matching rule with Date < rule expoch.
* Set the upstream header for matching rule.
* DONE.

Find Matching Rule:
* If current transaction is not cache hit, find newest matching rule.
* Set the upstream header to matching rule.
* DONE.

In order to pass a message along the rule regex will be percent
encoded as part of the header message.
The rule regex is decoded before signature check.

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

Rules can be removed by removing the rule from the rules file
and either running `traffic_ctl config reload` or
`traffic_ctl plugin msg revalidate reload`.
This will reset the current in memory rules list and key file, including
the current rule version.

Examples
========

The following rule would cause the cache object whose origin server is
``origin.tld`` and whose path is ``/images/foo.jpg`` to be revalidated
in |TS| until 6:47:27 AM on Saturday, November 14th, 2015 (UTC)::

    http://origin\.tld/images/foo\.jpg 1447483647 1

Note the escaping of the ``.`` metacharacter in the rule's regular expression.
