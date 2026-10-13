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
"""proxy.config.http.server_response_header_timeout retires an HTTP/2 origin session it fires on."""

import http.client
import re
import sys
import time
from pathlib import Path

from tools.uranium.services import ATSFactory, ServiceFactory
from .origin_test_helpers import configure_h2_origin, finish_origin

RESPONSE_HEADER_TIMEOUT = 1
INACTIVITY_TIMEOUT = 30


def get(port: int, path: str) -> int:
    """Send one HTTP/1.1 request through ATS and return the response status."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=INACTIVITY_TIMEOUT * 2)
    try:
        connection.request("GET", path, headers={"Host": "origin.example.com"})
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def test_h2_origin_session_retired_by_response_header_timeout(ats_factory: ATSFactory, services: ServiceFactory) -> None:
    """Cut off an unanswered HTTP/2 origin stream early, count it, and stop using its session.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Runs the origin.
    """
    port = services.allocate_port()
    ats = configure_h2_origin(
        ats_factory,
        port,
        disable_log_checks=True,
        **{
            "proxy.config.http.server_response_header_timeout": RESPONSE_HEADER_TIMEOUT,
            "proxy.config.http.transaction_no_activity_timeout_out": INACTIVITY_TIMEOUT,
            "proxy.config.http.connect_attempts_max_retries": 0,
        },
    )
    stop = ats.run_directory / "stop-origin"
    ssl = Path(__file__).parents[2] / "tools/ssl"
    origin = services.process(
        "origin",
        [
            sys.executable,
            Path(__file__).with_name("stalled_stream_origin.py"),
            str(port),
            ssl / "server.pem",
            ssl / "server.key",
            stop,
        ],
        ready_port=port,
    )
    origin.start()
    ats.start()

    assert get(ats.http_port, "/ok-before") == 200
    origin.wait_for_output(r"^conn 1 request stream=\d+ path=/ok-before$")

    started = time.monotonic()
    assert get(ats.http_port, "/stall") == 504
    elapsed = time.monotonic() - started
    assert elapsed < INACTIVITY_TIMEOUT / 2, elapsed

    # The session that held the unanswered stream takes no new streams and closes, having none left.
    assert get(ats.http_port, "/ok-after") == 200
    output = origin.wait_for_output(r"^conn \d+ request stream=\d+ path=/ok-after$")
    assert re.search(r"^conn 2 request stream=\d+ path=/ok-after$", output, re.MULTILINE), output
    origin.wait_for_output(r"^conn 1 eof")

    result = ats.traffic_ctl("metric", "get", "proxy.process.http.server_response_header_timeouts")
    assert result.returncode == 0, result.output
    assert int(result.stdout.split()[-1]) == 1, result.stdout

    finish_origin(services, origin, stop)
    ats.stop()
    assert "Traceback" not in origin.output, origin.output
    diags = ats.diags_log.read_text(errors="replace")
    assert not re.search("FATAL:|Unrecognized configuration value", diags), diags
