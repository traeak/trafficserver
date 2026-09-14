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
is resolved against the Traffic Server configuration directory. Choose one mode
for a given transaction: if both apply, the transaction is inspected by each
instance against its own rules.

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

 - Download the [Core Rule Set](https://github.com/coreruleset/coreruleset)
 - Copy `crs-setup.conf.example` next to the rules as `crs-setup.conf`, and the
   `rules` directory alongside it
 - Copy `owasp.conf` from this directory into the same place, and name it in
   `plugin.config` or in the remap rule's `@pparam`

To test, send a request with a `User-Agent: Nikto` header; the default action
logs a message to `traffic.out`.

## Limitations

> **Warning:** response phase rules run only on responses fetched from the
> origin. A cache hit never reaches `TS_HTTP_READ_RESPONSE_HDR_HOOK`, so the
> response rules silently skip it. Request phase rules run on every transaction.

These apply to both modes.

 - No `REQUEST_BODY` inspection. The request body would have to be buffered in
   full before it could be forwarded to the origin.
 - No `RESPONSE_BODY` inspection. The body would have to be decompressed first,
   which is expensive for a proxy. See
   https://github.com/SpiderLabs/ModSecurity/issues/2494.
 - Rules that depend on those bodies never match, and are best removed with
   `SecRuleRemoveById`.
 - A `redirect:` target containing a control character is discarded (the
   request is still blocked). Macros there expand to decoded request data, so
   prefer static redirect targets.
