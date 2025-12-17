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
    #    options={
    #        "--key": "{0}/signed-foo.key".format(Test.RunDirectory),
    #        "--cert": "{0}/signed-foo.pem".format(Test.RunDirectory),
    #    },
)
server_bar = Test.MakeOriginServer(
    "server_bar",
    ssl=True,
    #    options={
    #        "--key": "{0}/signed-bar.key".format(Test.RunDirectory),
    #        "--cert": "{0}/signed-bar.pem".format(Test.RunDirectory),
    #    },
)

# default check request/response
request_foo_header = {"headers": "GET / HTTP/1.1\r\nHost: foo.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_foo_header = {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": "foo ok"}
request_bar_header = {"headers": "GET / HTTP/1.1\r\nHost: bar.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_bar_header = {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": "bar ok"}

server_foo.addResponse("sessionlog.json", request_foo_header, response_foo_header)
server_bar.addResponse("sessionlog.json", request_bar_header, response_bar_header)

request_bar_header = {"headers": "GET /path HTTP/1.1\r\nHost: bar.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_bar_header = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": "path bar ok"
}

server_bar.addResponse("sessionlog.json", request_bar_header, response_bar_header)

ts.addSSLfile("ssl/server-foo.pem")
ts.addSSLfile("ssl/server-foo.key")
ts.addSSLfile("ssl/server-bar.pem")
ts.addSSLfile("ssl/server-bar.key")
#ts.addSSLfile("ssl/server.pem")
#ts.addSSLfile("ssl/server.key")
ts.addSSLfile("ssl/signer.pem")
ts.addSSLfile("ssl/signer.key")

ts.Disk.ssl_multicert_config.AddLines(
    [
        "ssl_cert_name=server-foo.pem ssl_key_name=server-foo.key",
        "ssl_cert_name=server-bar.pem ssl_key_name=server-bar.key",
    ])

dns = Test.MakeDNServer("dns")

ts.Disk.records_config.update(
    {
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'http|next_hop|parent|ssl|header_rewrite',
        'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
        # set global policy
        #'proxy.config.ssl.client.verify.server.policy': 'ENFORCED',
        'proxy.config.ssl.client.verify.server.policy': 'PERMISSIVE',
        'proxy.config.ssl.client.verify.server.properties': 'NAME',
        'proxy.config.ssl.client.CA.cert.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.ssl.client.CA.cert.filename': 'signer.pem',
        'proxy.config.url_remap.pristine_host_hdr': 0,
        'proxy.config.dns.nameservers': '127.0.0.1:{0}'.format(dns.Variables.Port),
        'proxy.config.dns.resolv_conf': 'NULL',
        'proxy.config.exec_thread.autoconfig.scale': 1.0,
        'proxy.config.ssl.client.sni_policy': 'host',
        'proxy.config.http.connect.down.policy': 1,  # tls failures don't mark down
    })

dns.addRecords(records={"foo.com.": ["127.0.0.1"]})
dns.addRecords(records={"bar.com.": ["127.0.0.1"]})

ts.Disk.remap_config.AddLines(
    [
        "map http://www.example.com https://www.example.com",
        #"@plugin=conf_remap.so @pparam=proxy.config.ssl.client.verify.server.properties=NAME",
    ])

ts.Disk.parent_config.AddLine(
    #'dest_domain=. port=443 parent="foo.com:{0}|1;bar.com:{1}|1" parent_retry=simple_retry parent_is_proxy=false go_direct=false simple_server_retry_responses="404" host_override=true'
    'dest_domain=. port=443 parent="foo.com:{0}|1;bar.com:{1}|1" parent_retry=simple_retry parent_is_proxy=false go_direct=false simple_server_retry_responses="404" host_override=true'
    .format(server_foo.Variables.SSL_Port, server_bar.Variables.SSL_Port))

curl_args = f"-s -L -o /dev/stdout -D /dev/stderr -x localhost:{ts.Variables.port}/"

tr = Test.AddTestRun("request with failover")
ps = tr.Processes.Default
ps.StartBefore(server_foo)
ps.StartBefore(server_bar)
ps.StartBefore(dns)
ps.StartBefore(Test.Processes.ts)
tr.MakeCurlCommand(curl_args + " http://www.example.com/path", ts=ts)
tr.StillRunningAfter = ts
ps.Streams.stdout = Testers.ContainsExpression("path bar ok", "Expected 200 response from bar.com")
