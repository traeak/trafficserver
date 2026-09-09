# waf

A web application firewall for Apache Traffic Server, backed by
[ModSecurity v3](https://github.com/owasp-modsecurity/ModSecurity)
(`libmodsecurity`). It works both as a global plugin and as a remap plugin.

For the full documentation see `doc/admin-guide/plugins/waf.en.rst`.

## Building

The plugin is built when `libmodsecurity` is found and experimental plugins are
enabled:

```
cmake -B build -DBUILD_EXPERIMENTAL_PLUGINS=ON
cmake --build build
```

Use `-DENABLE_WAF=ON` to make a missing `libmodsecurity` a configure error
rather than silently skipping the plugin.

## Configuring

As a global plugin, add it to `plugin.config` with one or more ModSecurity rule
files:

```
waf.so waf/example.conf
```

As a remap plugin, pass the rule files as pparams:

```
map http://example.com/ http://origin/ @plugin=waf.so @pparam=waf/example.conf
```

A relative path is resolved against the Traffic Server configuration directory.

The global instance reloads its rule files with:

```
traffic_ctl plugin msg waf reload
```

If a reload fails to parse, the previously loaded rules stay in effect. Remap
instances pick up rule changes on `traffic_ctl config reload`.

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
 - Copy `owasp.conf` from this directory into the same place and point
   `plugin.config` at it

To test, send a request with a `User-Agent: Nikto` header; the default action
logs a message to `traffic.out`.

## Limitations

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
 - The response phases run on origin responses only; a cache hit does not reach
   `TS_HTTP_READ_RESPONSE_HDR_HOOK`. Request phase rules run on every
   transaction.
