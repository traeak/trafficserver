'''
'''
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
import time
from jsonrpc import Request

Test.Summary = '''
Revalidate propagation test.
'''

# Test description:
# 2 edges, 1 mid
# Load up caches.
# Load with configs: (edge0, mid, edge1) oldest to newest configs.
#
# Do config files need timestamping?

Test.testName = "revalidate_prop"

Test.SkipUnless(Condition.PluginExists('revalidate.so'), Condition.PluginExists('xdebug.so'))

# set up proxy verifier
"""Initialize test"""
preload_file = "replay/revalidate_preload.replay.yaml"
server = Test.MakeVerifierServerProcess("server", preload_file)


def MakeATSInstance(name, server_port):
    ats = Test.MakeATSProcess(name)

    # Configure ATS servers
    ats.Disk.plugin_config.AddLines([
        'xdebug.so --enable=x-cache',
        'revalidate.so --rule-path=reval.conf',
    ])

    ats.Disk.records_config.update(
        {
            'proxy.config.diags.debug.enabled': 1,
            'proxy.config.diags.debug.tags': 'revalidate',
            'proxy.config.http.insert_request_via_str': 0,
            'proxy.config.http.insert_response_via_str': 2,
            'proxy.config.http.response_via_str': name,
        })

    ats.Disk.logging_yaml.AddLine(
        '''logging:
 formats:
  - name: custom
    format: '%<cquuc> %<pssc> %<crc>'
 logs:
  - filename: transaction
    format: custom
''')

    ats_path = os.path.join(ats.Variables.CONFIGDIR, 'reval.conf')
    ats.Disk.File(ats_path, typename="ats:config").AddLine("# empty")

    ats.Disk.remap_config.AddLines([f"map / http://127.0.0.1:{server_port}"])

    return ats


""" Configure ATS instances """
mid = MakeATSInstance("mid", server.Variables.http_port)
edge0 = MakeATSInstance("edge0", mid.Variables.port)
edge1 = MakeATSInstance("edge1", mid.Variables.port)

Test.Setup.Copy("metrics.sh")

timenow = time.time()
expiry = int(timenow) + 600

# config paths
mid_path = os.path.join(mid.Variables.CONFIGDIR, 'reval.conf')
edge0_path = os.path.join(edge0.Variables.CONFIGDIR, 'reval.conf')
edge1_path = os.path.join(edge1.Variables.CONFIGDIR, 'reval.conf')

# proxy ports
edge0_proxy = f' -x 127.0.0.1:{edge0.Variables.port}'
edge1_proxy = f' -x 127.0.0.1:{edge1.Variables.port}'

curl_and_args = 'curl -s -D - -v -H "x-debug: x-cache"'
""" Test """

# preload cache vars

# 0 Test - Preload the cache, edge0
tr = Test.AddTestRun("Preload edge0")
ps = tr.Processes.Default
ps.StartBefore(server)
ps.StartBefore(mid)
ps.StartBefore(edge0)
ps.StartBefore(edge1)
tr.AddVerifierClientProcess("client0", preload_file, http_ports=[edge0.Variables.port])
ps.ReturnCode = 0

# 1 Test - Preload the cache, edge1
tr = Test.AddTestRun("Preload edge1")
ps = tr.Processes.Default
tr.AddVerifierClientProcess("client1", preload_file, http_ports=[edge1.Variables.port])
ps.ReturnCode = 0

# 2 Update mid config (mid config)
tr = Test.AddTestRun("Load mid config")
ps = tr.Processes.Default
tr.DelayStart = 1
tr.Disk.File(
    mid_path, typename="ats:config").AddLines([
        f"bar {expiry} 2",
    ])
tr.StillRunningAfter = mid
tr.AddJsonRPCClientRequest(mid, Request.admin_config_reload())
ps.ReturnCode = 0
ps.TimeOut = 5
tr.TimeOut = 5

# 3 Update edge0 config (oldest config)
tr = Test.AddTestRun("Load edge0 config")
ps = tr.Processes.Default
tr.DelayStart = 1
tr.Disk.File(
    edge0_path, typename="ats:config").AddLines([
        f"foo {expiry} 1",
        f"bar {expiry} 2",
    ])
tr.StillRunningAfter = edge0
tr.AddJsonRPCClientRequest(edge0, Request.admin_config_reload())
ps.ReturnCode = 0
ps.TimeOut = 5
tr.TimeOut = 5

# 4 Update edge1 config (newest config)
tr = Test.AddTestRun("Load edge1 config")
ps = tr.Processes.Default
tr.DelayStart = 1
tr.Disk.File(
    edge1_path, typename="ats:config").AddLines([
        f"bar {expiry} 2",
        f"baz {expiry} 3",
    ])
tr.StillRunningAfter = edge1
tr.AddJsonRPCClientRequest(edge1, Request.admin_config_reload())
ps.ReturnCode = 0
ps.TimeOut = 5
tr.TimeOut = 5

# 5 foo through edge0
tr = Test.AddTestRun("foo through edge0")
ps = tr.Processes.Default
ps.Command = curl_and_args + ' http://example.com/foo -H "uuid: 1"' + edge0_proxy
ps.ReturnCode = 0
ps.Streams.stdout.Content = Testers.ContainsExpression("X-Cache: hit-stale", "expected cache hit stale")
ps.Streams.stdout.Content += Testers.ContainsExpression(r"mid \[cHs f \]", "unexpected mid via string")
ps.Streams.stdout.Content += Testers.ContainsExpression(r"edge0 \[cSsSfU\]", "unexpected edge via string")

# 6 foo through edge1 - mid returns 304
tr = Test.AddTestRun("foo through edge1")
ps = tr.Processes.Default
ps.Command = curl_and_args + ' http://example.com/foo -H "uuid: 1"' + edge1_proxy
ps.ReturnCode = 0
ps.Streams.stdout.Content = Testers.ContainsExpression("X-Cache: hit-fresh", "expected cache hit fresh")
ps.Streams.stdout.Content += Testers.ContainsExpression(r"mid \[cHs f \]", "unexpected mid via string")
ps.Streams.stdout.Content += Testers.ContainsExpression(r"edge1 \[cHs f \]", "unexpected edge via string")

# 7 bar through edge0 - origin returns hit
tr = Test.AddTestRun("bar through edge0")
ps = tr.Processes.Default
ps.Command = curl_and_args + ' http://example.com/bar -H "uuid: 2"' + edge0_proxy
ps.ReturnCode = 0
ps.Streams.stdout.Content = Testers.ContainsExpression("X-Cache: hit-stale", "expected cache hit stale")
ps.Streams.stdout.Content += Testers.ContainsExpression(r"mid \[cSsSfU\]", "unexpected mid via string")
ps.Streams.stdout.Content += Testers.ContainsExpression(r"edge0 \[cSsSfU\]", "unexpected edge via string")

# 8 bar through edge1 - mid now returns hit
tr = Test.AddTestRun("bar through edge1")
ps = tr.Processes.Default
ps.Command = curl_and_args + ' http://example.com/bar -H "uuid: 2"' + edge1_proxy
ps.ReturnCode = 0
ps.Streams.stdout.Content = Testers.ContainsExpression("X-Cache: hit-stale", "expected cache hit stale")
ps.Streams.stdout.Content += Testers.ContainsExpression(r"mid \[cHs f \]", "unexpected mid via string")
ps.Streams.stdout.Content += Testers.ContainsExpression(r"edge1 \[cSsSfU\]", "unexpected edge via string")

# 9 baz through edge0 - edge returns hit (rule not there yet)
tr = Test.AddTestRun("baz through edge0")
ps = tr.Processes.Default
ps.Command = curl_and_args + ' http://example.com/baz -H "uuid: 3"' + edge0_proxy
ps.ReturnCode = 0
ps.Streams.stdout.Content = Testers.ContainsExpression("X-Cache: hit-fresh", "expected cache hit fresh")
#ps.Streams.stdout.Content += Testers.ContainsExpression("mid \[cSsSfU\]", "unexpected mid via string")
ps.Streams.stdout.Content += Testers.ContainsExpression(r"edge0 \[cHs f \]", "unexpected edge via string")

# 10 baz through edge1 - mid adds rule and request through to origin
tr = Test.AddTestRun("baz through edge1")
ps = tr.Processes.Default
ps.Command = curl_and_args + ' http://example.com/baz -H "uuid: 3"' + edge1_proxy
ps.ReturnCode = 0
ps.Streams.stdout.Content = Testers.ContainsExpression("X-Cache: hit-stale", "expected cache hit stale")
ps.Streams.stdout.Content += Testers.ContainsExpression(r"mid \[cSsSfU\]", "unexpected mid via string")
ps.Streams.stdout.Content += Testers.ContainsExpression(r"edge1 \[cSsSfU\]", "unexpected edge via string")
