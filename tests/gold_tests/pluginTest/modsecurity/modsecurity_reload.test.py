'''Verify traffic_ctl config reload picks up a changed rule file of the global plugin.'''
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import os

Test.Summary = __doc__

Test.SkipUnless(Condition.PluginExists('modsecurity.so'))
Test.ContinueOnFail = False

RULES_FILE = 'modsecurity_reload_rules.conf'
BLOCK_FIRST = 'SecRule REQUEST_HEADERS:X-Test "@streq first" "id:9001,phase:1,deny,status:403"'
BLOCK_SECOND = 'SecRule REQUEST_HEADERS:X-Test "@streq second" "id:9002,phase:1,deny,status:403"'

server = Test.MakeOriginServer('server')
server.addResponse(
    'sessionlog.json', {
        'headers': 'GET /reload HTTP/1.1\r\nHost: example.com\r\n\r\n',
        'timestamp': '1469733493.993',
        'body': '',
    }, {
        'headers': 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n',
        'timestamp': '1469733493.993',
        'body': '',
    })

ts = Test.MakeATSProcess('ts', enable_cache=False)
ts.Disk.records_config.update(
    {
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'modsecurity|config.reload',
    })
ts.Disk.MakeConfigFile(RULES_FILE).AddLines(['SecRuleEngine On', BLOCK_FIRST])
ts.Disk.plugin_config.AddLine(f'modsecurity.so {RULES_FILE}')
ts.Disk.remap_config.AddLine(f'map http://example.com/ http://127.0.0.1:{server.Variables.Port}/')


def add_request(description: str, header_value: str, expected_status: str, start: bool = False) -> None:
    tr = Test.AddTestRun(description)
    if start:
        tr.Processes.Default.StartBefore(server, ready=When.PortOpen(server.Variables.Port))
        tr.Processes.Default.StartBefore(ts)
    tr.MakeCurlCommand(
        f"-s -o /dev/null -w '%{{http_code}}' -H 'Host: example.com' -H 'X-Test: {header_value}' "
        f"http://127.0.0.1:{ts.Variables.port}/reload",
        ts=ts)
    tr.Processes.Default.ReturnCode = 0
    tr.Processes.Default.Streams.stdout.Content = Testers.ContainsExpression(
        f'^{expected_status}$', f'X-Test: {header_value} should get a {expected_status}')
    tr.StillRunningAfter = ts
    tr.StillRunningAfter = server


add_request('Before the reload, the first rule blocks', 'first', '403', start=True)
add_request('Before the reload, the second value passes', 'second', '200')

# The rule file is rewritten when the reload test run starts, after the delay,
# so that its modification time differs from the original one.
reload = Test.AddConfigReload(
    ts, expect_tasks={'modsecurity': 'success'}, delay_start=1, description='Replace the rule file and reload the configuration')
reload.Disk.File(
    os.path.join(ts.Variables.CONFIGDIR, RULES_FILE), typename='ats:config').AddLines(['SecRuleEngine On', BLOCK_SECOND])
reload.StillRunningAfter = server

add_request('After the reload, the first value passes', 'first', '200')
add_request('After the reload, the second rule blocks', 'second', '403')
