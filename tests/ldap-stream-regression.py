#!/usr/bin/env python3
#
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
"""Exercise the legacy LDAP backend without an external LDAP server.

Usage: python3 ldap-stream-regression.py /path/to/curl
The binary must use lib/ldap.c (not the separate OpenLDAP backend).
"""
import os
import socket
import subprocess
import sys
import threading
import time


def tlv(tag, body):
    size = len(body)
    length = bytes([size]) if size < 128 else (
        bytes([0x80 + (size.bit_length() + 7) // 8]) +
        size.to_bytes((size.bit_length() + 7) // 8, "big"))
    return bytes([tag]) + length + body


def receive_message(conn):
    def exact(size):
        body = b""
        while len(body) < size:
            chunk = conn.recv(size - len(body))
            if not chunk:
                raise EOFError()
            body += chunk
        return body
    header = exact(2)
    size = header[1]
    if size & 128:
        size = int.from_bytes(exact(size & 127), "big")
    return exact(size)


def run_case(binary, mode):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(4)
        errors = []

        def serve_connection(conn):
            try:
                with conn:
                    conn.settimeout(4)
                    bind = receive_message(conn)
                    conn.sendall(tlv(0x30, bind[:3] +
                                 b"\x61\7\x0a\1\0\4\0\4\0"))
                    message_id = receive_message(conn)[:3]
                    attr = tlv(0x30, tlv(4, b"description") +
                               tlv(0x31, tlv(4, b"x" * 16384)))
                    entry = tlv(0x30, message_id + tlv(0x64,
                                tlv(4, b"cn=test") + tlv(0x30, attr)))
                    conn.sendall(entry)
                    if mode in ("filesize", "timeout"):
                        # curl must act on the entry before SearchResultDone.
                        time.sleep(2)
                    code = 4 if mode == "sizelimit" else (
                        50 if mode == "error" else 0)
                    conn.sendall(tlv(0x30, message_id +
                                 b"\x65\7\x0a\1" + bytes([code]) +
                                 b"\4\0\4\0"))
            except (BrokenPipeError, ConnectionResetError,
                    EOFError, socket.timeout):
                pass
            except Exception as exc:
                errors.append(exc)

        def server():
            # The legacy backend can open a separate SDK connection after the
            # transport socket has connected. Service both independently.
            while True:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                threading.Thread(target=serve_connection, args=(conn,),
                                 daemon=True).start()

        worker = threading.Thread(target=server, daemon=True)
        worker.start()
        args = [binary, "-sS", "--noproxy", "*", "--max-time",
                "1" if mode == "timeout" else "4",
                f"ldap://127.0.0.1:{listener.getsockname()[1]}/"]
        if mode == "filesize":
            args += ["--max-filesize", "1024"]
        start = time.monotonic()
        result = subprocess.run(args, capture_output=True, timeout=6,
                                env=dict(os.environ, NO_PROXY="*", no_proxy="*"))
        elapsed = time.monotonic() - start
        listener.close()
        worker.join(0.1)
        assert not errors, errors
        expected = {"filesize": 63, "timeout": 28, "error": 39}.get(mode, 0)
        assert result.returncode == expected, result.stderr
        if mode == "filesize":
            assert elapsed < 1.5, elapsed
            assert len(result.stdout) <= 1024
        elif mode == "timeout":
            assert elapsed < 1.8, elapsed
        else:
            assert b"description: " + b"x" * 16384 in result.stdout
        print(f"PASS {mode}: code={result.returncode} "
              f"bytes={len(result.stdout)} seconds={elapsed:.3f}")


if __name__ == "__main__":
    for scenario in ("filesize", "timeout", "success", "sizelimit", "error"):
        run_case(sys.argv[1], scenario)
