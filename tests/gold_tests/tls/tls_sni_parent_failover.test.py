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

Test.Summary = '''
Test parent failover sni name
'''

# Verify proxy.config.http.cache.ignore_authentication behavior.
#Test.ATSReplayTest(replay_file="replay/tls_sni_parent_failover.replay.yaml")

# Define default ATS
ts = Test.MakeATSProcess("ts", enable_tls=True)

server_foo = Test.MakeOriginServer(
    "server_foo",
    ssl=True,
)
server_bar = Test.MakeOriginServer(
    "server_bar",
    ssl=True,
)

request_foo_header = {"headers": "GET / HTTP/1.1\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_foo_header = {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": "foo ok"}

request_bar_header = {"headers": "GET / HTTP/1.1\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_bar_header = {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": "bar ok"}

server_foo.addResponse("sessionlog.json", request_foo_header, response_foo_header)
server_bar.addResponse("sessionlog.json", request_bar_header, response_bar_header)

ts.addSSLfile("ssl/server_foo.pem")
ts.addSSLfile("ssl/server_foo.key")
ts.addSSLfile("ssl/server_bar.pem")
ts.addSSLfile("ssl/server_bar.key")

ts.Disk.ssl_multicert_config.AddLine('dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key')

dns = Test.MakeDNServer("dns")
dns.addRecords(records={"foo.com.": ["127.0.0.1"]})
dns.addRecords(records={"bar.com.": ["127.0.0.1"]})

ts.Disk.records_config.update(
    {
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'ssl',
        'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
        # set global policy
        'proxy.config.ssl.client.verify.server.policy': 'PERMISSIVE',
        'proxy.config.ssl.client.verify.server.properties': 'ALL',
        'proxy.config.ssl.client.CA.cert.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.ssl.client.CA.cert.filename': 'signer.pem',
        'proxy.config.url_remap.pristine_host_hdr': 1,
        'proxy.config.dns.nameservers': '127.0.0.1:{0}'.format(dns.Variables.Port),
        'proxy.config.dns.resolv_conf': 'NULL',
        'proxy.config.exec_thread.autoconfig.scale': 1.0,
        'proxy.config.ssl.client.sni_policy': 'host'
    })

ts.Disk.remap_config.AddLine("map http:// https://example.com @plugin=header_rewrite.so @pparam=hdr_rw.config")

ts.Disk.parent_config.AddLine(
    'dest_domain="." port=443 parent="foo.com:443|1" secondary_parent="bar.com:443|1" go_direct=false host_override=true')

ts.Disk.MakeConfigFile("hdr_rw.config").AddLines(
    [
        'cond %{READ_RESPONSE_HDR_HOOK}',
        'cond %{HEADER:@FirstTime} =""',
        'set-header @FirstTime false',
        'set-status 404',
    ])

curl_args = f"-s -o /dev/stdout -D /dev/stderr -v -x localhost:{ts.Variables.port}/"

tr = Test.AddTestRun("request with failover")

ps = tr.Processes.Default
ps.Default.StartBefore(server_foo)
ps.Default.StartBefore(server_bar)
ps.Default.StartBefore(Test.Processes.ts)
tr.MakeCurlCommand(curl_args + " http://nhp_hr/path", ts=ts)
tr.StillRunningAfter = ts
