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
"""proxy.config.http.server_response_header_timeout covers only the wait for the origin's response."""

import socket
import sys
import time
from pathlib import Path

import pytest

from tools.uranium.services import ATS, ATSFactory, ProcessService, ServiceFactory

DIRECTORY = Path(__file__).parent
METRIC = "proxy.process.http.server_response_header_timeouts"
RESPONSE_HEADER_TIMEOUT = 1
INACTIVITY_TIMEOUT = 30


def start_origin(services: ServiceFactory, mode: str) -> tuple[ProcessService, int]:
    """Start the test origin and return it with its port.

    :param services: Factory owning the origin's cleanup.
    :param mode: "answer" to answer once the whole request arrived, "hold" to never read.
    """
    port = services.allocate_port()
    origin = services.process("origin", [sys.executable, DIRECTORY / "response_header_origin.py", str(port), mode], ready_port=port)
    origin.start()
    return origin, port


def start_ats(ats_factory: ATSFactory, origin_port: int, *, request_transform: bool = False, **records: object) -> ATS:
    """Start ATS with a response header timeout well below the origin inactivity timeout.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param origin_port: Port of the test origin.
    :param request_transform: Load a pass-through request body transform.
    :param records: Additional record values.
    """
    ats = ats_factory.create("ts", enable_cache=False, disable_log_checks=True)
    ats.records.update(
        {
            "proxy.config.http.server_response_header_timeout": RESPONSE_HEADER_TIMEOUT,
            "proxy.config.http.transaction_no_activity_timeout_out": INACTIVITY_TIMEOUT,
            "proxy.config.http.connect_attempts_max_retries": 0,
            "proxy.config.diags.debug.enabled": 1,
            "proxy.config.diags.debug.tags": "http",
            **records,
        }
    )
    ats.remap_config.add_line(f"map / http://127.0.0.1:{origin_port}/")
    if request_transform:
        ats.copy_custom_plugin("{AtsTestPluginsDir}/tunnel_transform.so")
        ats.plugin_config.add_line("tunnel_transform.so request_hdr")
    ats.start()
    return ats


def read_status(connection: socket.socket) -> int:
    """Read a response until the peer closes and return its status code."""
    data = b""
    while chunk := connection.recv(65536):
        data += chunk
    assert data.startswith(b"HTTP/1.1 "), data[:200]
    return int(data.split(b" ", 2)[1])


def metric(ats: ATS) -> int:
    """Return the response header timeout counter."""
    result = ats.traffic_ctl("metric", "get", METRIC)
    assert result.returncode == 0, result.output
    return int(result.stdout.split()[-1])


def finish(ats: ATS) -> None:
    """Stop ATS and require clean diagnostics."""
    ats.stop()
    diags = ats.diags_log.read_text(errors="replace")
    assert "FATAL:" not in diags, diags


@pytest.mark.parametrize("request_transform", [False, True], ids=["plain", "transform"])
def test_slow_upload_is_not_cut_off(request_transform: bool, ats_factory: ATSFactory, services: ServiceFactory) -> None:
    """A request body that pauses for longer than the timeout still completes.

    The origin cannot answer before it has the body, so the wait for the response header begins only
    once the body has been sent, whether or not a request transform sits in between.

    :param request_transform: Send the body through a request transform.
    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Runs the origin.
    """
    origin, port = start_origin(services, "answer")
    ats = start_ats(ats_factory, port, request_transform=request_transform)

    body = b"x" * 64
    head = f"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    with socket.create_connection(("127.0.0.1", ats.http_port), timeout=INACTIVITY_TIMEOUT) as client:
        client.sendall(head.encode() + body[:32])
        origin.wait_for_output(r"^headers /upload$")
        time.sleep(RESPONSE_HEADER_TIMEOUT * 3)
        client.sendall(body[32:])
        assert read_status(client) == 200
    origin.wait_for_output(rf"^body /upload {len(body)}$")
    assert metric(ats) == 0

    finish(ats)


def test_request_write_stall_is_not_counted(ats_factory: ATSFactory, services: ServiceFactory) -> None:
    """An origin that stops reading the request is cut off by the timeout but not counted by it.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Runs the origin.
    """
    _, port = start_origin(services, "hold")
    ats = start_ats(
        ats_factory,
        port,
        **{
            "proxy.config.http.request_header_max_size": 1 << 20,
            "proxy.config.net.sock_send_buffer_size_out": 4096,
        },
    )

    # Far more than the origin's receive buffer and ATS's send buffer can hold between them, split to stay
    # under the per-field limit.
    padding = "".join(f"X-Padding-{index}: {'p' * 16384}\r\n" for index in range(32))
    request = f"GET /stall HTTP/1.1\r\nHost: example.com\r\n{padding}Connection: close\r\n\r\n"
    with socket.create_connection(("127.0.0.1", ats.http_port), timeout=INACTIVITY_TIMEOUT) as client:
        started = time.monotonic()
        client.sendall(request.encode())
        status = read_status(client)
        elapsed = time.monotonic() - started
    assert status == 504
    assert elapsed < INACTIVITY_TIMEOUT / 2, elapsed
    assert metric(ats) == 0

    finish(ats)
