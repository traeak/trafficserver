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
"""HTTP/1.1 origin for exercising the wait between sending a request and the response header.

In "answer" mode it prints "headers <path>" once it has a request header, reads the whole
Content-Length body, prints "body <path> <bytes>" and answers 200 at once.

In "hold" mode it accepts connections with a small receive buffer and never reads from them, so a
large request stalls partway through being written.
"""

import argparse
import socket
import sys
import threading

HOLD_RECEIVE_BUFFER = 4096


def say(message: str) -> None:
    """Print one line for the test to wait on."""
    print(message, flush=True)


def read_request_header(connection: socket.socket) -> tuple[str, int, bytes] | None:
    """Return the request path, its Content-Length and any body bytes read past the header."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(65536)
        if not chunk:
            return None
        data += chunk
    header, _, rest = data.partition(b"\r\n\r\n")
    lines = header.decode("latin-1").split("\r\n")
    path = lines[0].split(" ")[1]
    length = 0
    for line in lines[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "content-length":
            length = int(value.strip())
    return path, length, rest


def answer(connection: socket.socket) -> None:
    """Read one request, including its body, and answer it."""
    with connection:
        request = read_request_header(connection)
        if request is None:
            return
        path, length, body = request
        say(f"headers {path}")
        while len(body) < length:
            chunk = connection.recv(65536)
            if not chunk:
                return
            body += chunk
        say(f"body {path} {len(body)}")
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")


def main() -> int:
    """Serve until the test stops the process."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", type=int)
    parser.add_argument("mode", choices=["answer", "hold"])
    arguments = parser.parse_args()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if arguments.mode == "hold":
        # Set before listen() so that accepted connections advertise the small window from the start.
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, HOLD_RECEIVE_BUFFER)
    listener.bind(("127.0.0.1", arguments.port))
    listener.listen(16)

    held: list[socket.socket] = []
    while True:
        connection, _ = listener.accept()
        if arguments.mode == "hold":
            held.append(connection)
            say("accepted")
        else:
            threading.Thread(target=answer, args=(connection,), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
