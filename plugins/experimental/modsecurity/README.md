# modsecurity

A web application firewall for Apache Traffic Server, backed by
[ModSecurity v3](https://github.com/owasp-modsecurity/ModSecurity)
(`libmodsecurity`). It works either as a global plugin or as a remap plugin.

For the full documentation see `doc/admin-guide/plugins/modsecurity.en.rst`.

## Building

The plugin is built when `libmodsecurity` is found and experimental plugins are
enabled:

```
cmake -B build -DBUILD_EXPERIMENTAL_PLUGINS=ON
cmake --build build
```

Use `-DENABLE_MODSECURITY=ON` to make a missing `libmodsecurity` a configure
error rather than silently skipping the plugin.

## Configuring

Global plugin: add it to `plugin.config` with one or more ModSecurity rule
files. It inspects every transaction.

```
modsecurity.so modsecurity/example.conf
```

Remap plugin: add it to a remap rule, passing the rule files as pparams. It
inspects only the transactions matching that rule.

```
map http://example.com/ http://origin/ @plugin=modsecurity.so @pparam=modsecurity/example.conf
```

In both modes the rule files are loaded in the order given, and a relative path
is resolved against the Traffic Server configuration directory.

## Using both modes

The global plugin and remap instances can run together: a system-wide baseline,
such as the OWASP CRS, in `plugin.config`, and endpoint-specific rules on the
remap rules of the endpoints that need them.

A matching transaction is inspected by both, each against its own rule set: the
global plugin first, then the remap instance if the request was not blocked.
Whichever instance blocks first decides the response, and the other neither
inspects nor counts it. A remap instance can only add to the baseline: its
`SecRuleRemoveById` affects only its own rules. Keep remap rule files to what is
specific to the endpoint, since the baseline already ran.

## Reloading rules

In both modes, `traffic_ctl config reload` reloads the rules when a named rule
file has changed. Files pulled in with `Include`, such as the CRS
`rules/*.conf`, are not watched: `touch` a named rule file after changing one.

Global plugin: the reload shows up as the `modsecurity` task in
`traffic_ctl config status`. If a rule file fails to parse, the task fails and
the previous rules stay in effect. At startup, a rule file that fails to parse
leaves every transaction uninspected until it is fixed and reloaded.
`traffic_ctl plugin msg modsecurity reload` forces a reload even when no file
changed, but always reports success, so check `error.log` after it.

Remap plugin: a changed rule file reloads `remap.config`, which recreates the
remap instances. A rule file that fails to parse fails the whole `remap.config`
load: on a reload the previous remap configuration stays in effect, and at
startup Traffic Server does not start.

## Responses

Response rules run on every response: an origin response as its headers arrive,
so a blocked response is never cached, and any other response, such as a cache
hit, just before it is sent. A cache hit cannot be redirected: an intervention
on one with a status below 400 responds with 403 instead.

## Statistics

Both modes update the same process wide counters of blocked transactions:

 - `proxy.process.plugin.modsecurity.interventions.request`
 - `proxy.process.plugin.modsecurity.interventions.response`
 - `proxy.process.plugin.modsecurity.redirects_dropped`

## Trying it out

`example.conf` contains a few rules to exercise the plugin:

 - deny any request with the query parameter `testparam=test2`, with a 403
 - redirect any request with the query parameter `testparam=test1` to
   `https://www.example.com/` with a 301
 - override any response carrying the header `test: 1` with a 403
 - redirect any response carrying the header `test: 2` to
   `https://www.example.com/` with a 301

## Working with the OWASP CRS

[coreruleset.org](https://coreruleset.org) publishes the OWASP Core Rule Set, up
to date generic attack detection rules for ModSecurity. It runs on top of a
base configuration made from two files in the
[ModSecurity repository](https://github.com/owasp-modsecurity/ModSecurity):
`modsecurity.conf-recommended` and `unicode.mapping`. The steps below build this
layout under the Traffic Server configuration directory:

```
modsecurity/
  crs.conf              owasp.conf from this directory
  modsecurity.conf      ModSecurity's modsecurity.conf-recommended
  unicode.mapping       ModSecurity's unicode.mapping
  crs/                  the downloaded CRS release
    crs-setup.conf      copied from crs-setup.conf.example
    plugins/
    rules/
```

1. Download a CRS release, extract it as `modsecurity/crs`, and copy
   `crs-setup.conf.example` to `crs-setup.conf`.
2. Fetch the two ModSecurity files from the tag that matches the installed
   libmodsecurity, for example `v3.0.14`:

   ```
   cd modsecurity
   curl -L -o modsecurity.conf https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3.0.14/modsecurity.conf-recommended
   curl -L -O https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3.0.14/unicode.mapping
   ```

3. In `modsecurity.conf`, set `SecRuleEngine On` (the recommended file only
   detects) and point `SecAuditLog` at a file Traffic Server can write. Keep the
   mapping file named `unicode.mapping`.
4. Copy `owasp.conf` from this directory to `modsecurity/crs.conf`.
5. Name `modsecurity/crs.conf` in `plugin.config` or in a remap rule's
   `@pparam`, and restart Traffic Server.
6. Send a request with a `User-Agent: Nikto` header: the CRS blocks it with a
   403.

See the admin guide for the details.

## Request body inspection

By default the request body is not inspected. Pass `--inspect-request-body` in
`plugin.config` or as a `@pparam` to inspect it:

```
modsecurity.so --inspect-request-body modsecurity/example.conf
```

The request is then held until its whole body has arrived, the body is handed to
ModSecurity, and the phase 2 rules run against it before the origin is
contacted. It needs `SecRequestBodyAccess On` in the rules and a non-zero
`proxy.config.http.post_copy_size`, which bounds the inspectable body size.
Buffering holds each such request in memory and stops its upload from streaming,
so enable it only where that cost is worth it.

## Limitations

These apply to both modes.

 - `REQUEST_BODY` is inspected only with `--inspect-request-body` (see below).
   Without it, request body rules cannot match.
 - No `RESPONSE_BODY` inspection. The body would have to be decompressed first,
   which is expensive for a proxy. See
   https://github.com/SpiderLabs/ModSecurity/issues/2494.
 - The `pause` action is not supported. libmodsecurity 3.0.14 refuses to load a
   rule file that uses it; should a later version accept it, the plugin logs a
   warning once and ignores the pause.
 - Rules that depend on those bodies never match, and are best removed with
   `SecRuleRemoveById`.
 - A `redirect:` target containing a control character is discarded (the
   request is still blocked). Macros there expand to decoded request data, so
   prefer static redirect targets.
