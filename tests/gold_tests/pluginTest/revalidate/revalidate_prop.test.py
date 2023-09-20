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
# Load up cache, ensure fresh
# Create regex reval rule, config reload:
#  ensure item is staled only once.
# Add a new rule, config reload:
#  ensure item isn't restaled again, but rule still in effect.
#
# If the rule disappears from revalidate.conf its still loaded!!
# A rule's expiry can't be changed after the fact!

Test.testName = "revalidate_prop"

Test.SkipUnless(
    Condition.PluginExists('revalidate.so'),
    #    Condition.PluginExists('xdebug.so')
)

# set up proxy verifier
"""Initialize test"""
preload_file = "replay/revalidate_preload.replay.yaml"
server = Test.MakeVerifierServerProcess("server", preload_file)


def MakeATSInstance(name, server_port):
    ats = Test.MakeATSProcess(name)

    # Configure ATS servers
    ats.Disk.plugin_config.AddLines([
        #        'xdebug.so --enable=x-cache',
        'revalidate.so --rule-path=reval.conf',
    ])

    ats.Disk.records_config.update({
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
'''
    )

    ats_path = os.path.join(ats.Variables.CONFIGDIR, 'reval.conf')
    ats.Disk.File(ats_path, typename="ats:config").AddLine("# empty")

    ats.Disk.remap_config.AddLines([
        f"map / http://127.0.0.1:{server_port}"
    ])

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

#curl_and_args = 'curl -s -D - -v -H "x-debug: x-cache"'
curl_and_args = 'curl -s -D - -v'  # -H "x-debug: x-cache"'

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

# 2 Update mid config (median config)
tr = Test.AddTestRun("Load mid config")
ps = tr.Processes.Default
tr.DelayStart = 1
tr.Disk.File(mid_path, typename="ats:config").AddLines([
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
tr.Disk.File(edge0_path, typename="ats:config").AddLines([
    f"foo {expiry} 1",
    f"bar {expiry} 1",
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
tr.Disk.File(edge1_path, typename="ats:config").AddLines([
    f"bar {expiry} 3",
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
ps.Streams.stderr.Content = Testers.ContainsExpression("X-Cache: miss", "expected cache miss")


"""

tr = Test.AddTestRun("Cache miss path1")
ps = tr.Processes.Default
ps.StartBefore(server)
ps.StartBefore(mid)
ps.StartBefore(edge0)
ps.Command = curl_and_args + ' http://example.com/foo -H "uuid: 1"'
ps.ReturnCode = 0
ps.Streams.stderr.Content = Testers.ContainsExpression("X-Cache: miss", "expected cache miss")


# 1 Test - Load cache (miss) for later test (path1a)
tr = Test.AddTestRun("Cache miss path1a")
ps = tr.Processes.Default
ps.Command = curl_and_args + ' http://example.com/path1a -H "uuid: 2"'
ps.ReturnCode = 0
ps.Streams.stderr.Content = Testers.ContainsExpression("X-Cache: miss", "expected cache miss")
tr.StillRunningAfter = edge
tr.StillRunningAfter = mid

# 2 Test - Load cache (miss) for later test (path2a)
tr = Test.AddTestRun("Cache miss path2a")
ps = tr.Processes.Default
ps.Command = curl_and_args + ' http://example.com/path2a -H "uuid: 3"'
ps.ReturnCode = 0
ps.Streams.stderr.Content = Testers.ContainsExpression("X-Cache: miss", "expected cache miss")
tr.StillRunningAfter = edge
tr.StillRunningAfter = mid

# 3 Test - Cache hit path1
tr = Test.AddTestRun("Cache hit fresh path1")
ps = tr.Processes.Default
ps.Command = curl_and_args + ' http://example.com/path1 -H "uuid: 1"'
ps.ReturnCode = 0
ps.Streams.stderr.Content = Testers.ContainsExpression("X-Cache: hit", "expected cache hit")
tr.StillRunningAfter = edge
tr.StillRunningAfter = mid

# 4 Stage - Reload new revalidate
tr = Test.AddTestRun("Reload config add path1")
ps = tr.Processes.Default
# Need a sufficient delay so that the modification time difference
# of the new config file versus the old is greater than the granularity
# of the time stamp used. (The config file write happens after the delay.)
tr.DelayStart = 1
tr.Disk.File(revalidate_conf_path, typename="ats:config").AddLines([
    path1_rule
])
tr.StillRunningAfter = edge
tr.StillRunningAfter = mid
tr.StillRunningAfter = server
tr.AddJsonRPCClientRequest(edge, Request.admin_config_reload())
ps.ReturnCode = 0
ps.TimeOut = 5
tr.TimeOut = 5

# 5 Test - Revalidate path1
tr = Test.AddTestRun("Revalidate stale path1")
ps = tr.Processes.Default
tr.DelayStart = 5
ps.Command = curl_and_args + ' http://example.com/path1 -H "uuid: 1"'
ps.ReturnCode = 0
ps.Streams.stderr.Content = Testers.ContainsExpression("X-Cache: hit-stale", "expected cache hit-stale")
tr.StillRunningAfter = edge
tr.StillRunningAfter = mid

# 6 Test - Cache hit (path1)
tr = Test.AddTestRun("Cache hit fresh path1")
ps = tr.Processes.Default
ps.Command = curl_and_args + ' http://example.com/path1 -H "uuid: 1"'
ps.ReturnCode = 0
ps.Streams.stderr.Content = Testers.ContainsExpression("X-Cache: hit", "expected cache hit")
tr.StillRunningAfter = edge
tr.StillRunningAfter = mid

# 7 Stage - Reload new revalidate
tr = Test.AddTestRun("Reload config add path2")
ps = tr.Processes.Default
# Need a sufficient delay so that the modification time difference
# of the new config file versus the old is greater than the granularity
# of the time stamp used. (The config file write happens after the delay.)
tr.DelayStart = 1
timenow = time.time()
tr.Disk.File(revalidate_conf_path, typename="ats:config").AddLines([
    path1_rule,
    'path2 {} {}'.format(int(timenow) + 700, int(timenow * 1000))
])
tr.StillRunningAfter = edge
tr.StillRunningAfter = mid
tr.StillRunningAfter = server
tr.AddJsonRPCClientRequest(edge, Request.admin_config_reload())
ps.ReturnCode = 0
ps.TimeOut = 5
tr.TimeOut = 5

# 8 Test - Cache hit (path1)
tr = Test.AddTestRun("Cache hit fresh path1")
ps = tr.Processes.Default
tr.DelayStart = 5
ps.Command = curl_and_args + ' http://example.com/path1 -H "uuid: 1"'
ps.ReturnCode = 0
ps.Streams.stderr.Content = Testers.ContainsExpression("X-Cache: hit", "expected cache hit")
tr.StillRunningAfter = edge
tr.StillRunningAfter = mid

# 9 Test - Cache stale (check rule is still loaded) (path1a)
tr = Test.AddTestRun("Revalidate stale path1a")
ps = tr.Processes.Default
ps.Command = curl_and_args + ' http://example.com/path1a -H "uuid: 2"'
ps.ReturnCode = 0
ps.Streams.stderr.Content = Testers.ContainsExpression("X-Cache: hit-stale", "expected cache hit-stale")
tr.StillRunningAfter = edge
tr.StillRunningAfter = mid

# The C version of revalidate doesn't allow an existing rule to
# be changed by a reload.

# 10 Stage - revalidate rewrite rule early expire
tr = Test.AddTestRun("Reload config change path2")
ps = tr.Processes.Default
# Need a sufficient delay so that the modification time difference
# of the new config file versus the old is greater than the granularity
# of the time stamp used. (The config file write happens after the delay.)
tr.DelayStart = 1
timenow = time.time()
tr.Disk.File(revalidate_conf_path, typename="ats:config").AddLines([
    path1_rule,
    'path2 {} {}\n'.format(int(timenow) - 100, int(timenow * 1000))
])
tr.StillRunningAfter = edge
tr.StillRunningAfter = mid
tr.StillRunningAfter = server
tr.AddJsonRPCClientRequest(edge, Request.admin_config_reload())
ps.ReturnCode = 0
ps.TimeOut = 5
tr.TimeOut = 5

# 11 Test - Cache hit (path2a)
tr = Test.AddTestRun("Cache hit path2a (expired rule)")
ps = tr.Processes.Default
tr.DelayStart = 5
ps.Command = curl_and_args + ' http://example.com/path2a -H "uuid: 3"'
ps.ReturnCode = 0
ps.Streams.stderr.Content = Testers.ContainsExpression("X-Cache: hit", "expected cache hit")
tr.StillRunningAfter = edge
tr.StillRunningAfter = mid

# wait for logs to write
condwaitpath = os.path.join(Test.Variables.AtsTestToolsDir, 'condwait')

# 12 look for ts transaction log
edgelog = os.path.join(edge.Variables.LOGDIR, 'transaction.log')
tr = Test.AddTestRun()
ps = tr.Processes.Default
ps.Command = (condwaitpath + ' 60 1 -f ' + edgelog)

# 13 check edge transaction log
tr = Test.AddTestRun()
ps = tr.Processes.Default
ps.Command = (f"cat {edgelog}")
tr.Streams.stdout = "gold/edge.log.gold"
ps.ReturnCode = 0

# 14 look for mid transaction log
midlog = os.path.join(mid.Variables.LOGDIR, 'transaction.log')
tr = Test.AddTestRun()
ps = tr.Processes.Default
ps.Command = (condwaitpath + ' 60 1 -f ' + midlog)

# 15 check mid transaction log
tr = Test.AddTestRun()
ps = tr.Processes.Default
ps.Command = (f"cat {midlog}")
tr.Streams.stdout = "gold/mid.log.gold"
ps.ReturnCode = 0
"""
