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
"""Verify the TSLogField API honors view lengths and rejected replacements."""

import re

from tools.uranium.services import ATS, ATSFactory, Curl, ServiceFactory, wait_for_file_lines

PLUGIN_NAME = "log_field_register"


def configure_ats(ats_factory: ATSFactory, origin_port: int) -> ATS:
    """Load the plugin and log its two registered fields for every transaction.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param origin_port: Port of the origin the remap rule forwards to.
    """

    ats = ats_factory.create("ts", enable_cache=False)
    ats.copy_custom_plugin(f"{{AtsTestPluginsDir}}/{PLUGIN_NAME}.so")
    ats.plugin_config.add_line(f"{PLUGIN_NAME}.so")
    ats.remap_config.add_line(f"map / http://127.0.0.1:{origin_port}")
    ats.set_logging_yaml(
        {
            "logging":
                {
                    "formats": [{
                        "name": "fields",
                        "format": "%<lfrs> %<lfrk>"
                    }],
                    "logs": [{
                        "filename": "fields",
                        "format": "fields"
                    }],
                }
        })
    return ats


def test_log_field_register(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """Fields registered from views log their values, and a bad replacement keeps the original.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    origin = services.origin("origin")
    origin.add_response(
        {"headers": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"},
        {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"},
    )
    ats = configure_ats(ats_factory, origin.port)

    origin.start()
    ats.start()
    result = curl.run_for(ats, f"--silent --show-error --header 'Host: example.com' http://127.0.0.1:{ats.http_port}/")
    assert result.returncode == 0, result.output

    content = wait_for_file_lines(ats.log_directory / "fields.log", r"^view kept$", 1)
    assert re.findall(r"^.*$", content.strip(), re.MULTILINE) == ["view kept"], content

    ats.stop()
    diags = ats.diags_log.read_text(errors="replace")
    assert f"[{PLUGIN_NAME}] all checks passed" in diags, diags
    assert f"[{PLUGIN_NAME}] FAIL" not in diags, diags
