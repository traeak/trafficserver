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
Basic revalidate plugin test
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

Test.SkipUnless(
    Condition.PluginExists('revalidate.so'),
    Condition.PluginExists('xdebug.so')
)

# set up proxy verifier
"""Initialize test"""
replay_file = "replay/revalidate.replay.yaml"
server = Test.MakeVerifierServerProcess("server", replay_file)

"""Configure ATS instances"""
mid = Test.MakeATSProcess("mid")

# Configure ATS servers
mid.Disk.plugin_config.AddLines([
    'xdebug.so --enable=x-cache',
    'revalidate.so --rule-path=revalidate.conf',
])

mid.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'revalidate',
    'proxy.config.http.insert_age_in_response': 0,
    'proxy.config.http.response_via_str': 3,
})

mid.Disk.logging_yaml.AddLine(
    '''logging:
 formats:
  - name: custom
    format: '%<cquuc> %<pssc> %<crc>'
 logs:
  - filename: transaction
    format: custom
'''
)

mid.Disk.remap_config.AddLines([
    f"map / http://127.0.0.1:{server.Variables.http_port}"
])

edge = Test.MakeATSProcess("edge")

edge.Disk.plugin_config.AddLines([
    'xdebug.so --enable=x-cache',
    'revalidate.so --rule-path=revalidate.conf',
])

edge.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'revalidate',
    'proxy.config.http.insert_age_in_response': 0,
    'proxy.config.http.response_via_str': 3,
})

edge.Disk.logging_yaml.AddLine(
    '''logging:
 formats:
  - name: custom
    format: '%<cquuc> %<pssc> %<{X-Cache}psh>'
 logs:
  - filename: transaction
    format: custom
'''
)

edge.Disk.remap_config.AddLines([
    f"map / http://127.0.0.1:{mid.Variables.port}"
])

Test.testName = "revalidate"
Test.Setup.Copy("metrics.sh")

revalidate_conf_path = os.path.join(edge.Variables.CONFIGDIR, 'revalidate.conf')
curl_and_args = f'curl -s -D - -v -H "x-debug: x-cache" -x 127.0.0.1:{edge.Variables.port}'

path1_rule = 'path1 {} STALE\n'.format(int(time.time()) + 600)

# Define first revision for when trafficserver starts
edge.Disk.File(revalidate_conf_path, typename="ats:config").AddLine(
    "# Empty"
)

mid.Disk.File(revalidate_conf_path, typename="ats:config").AddLine(
    "# Empty"
)

# 0 Test - Load cache (miss) (path1)
tr = Test.AddTestRun("Cache miss path1")
ps = tr.Processes.Default
ps.StartBefore(server)
ps.StartBefore(edge)
ps.StartBefore(mid)
ps.Command = curl_and_args + ' http://example.com/path1 -H "uuid: 1"'
ps.ReturnCode = 0
ps.Streams.stderr.Content = Testers.ContainsExpression("X-Cache: miss", "expected cache miss")
tr.StillRunningAfter = edge
tr.StillRunningAfter = mid

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
tr.Disk.File(revalidate_conf_path, typename="ats:config").AddLines([
    path1_rule,
    'path2 {} STALE\n'.format(int(time.time()) + 700)
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
tr.Disk.File(revalidate_conf_path, typename="ats:config").AddLines([
    path1_rule,
    'path2 {} STALE\n'.format(int(time.time()) - 100),
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
