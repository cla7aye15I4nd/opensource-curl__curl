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
"""Run against a built curl: python3 tftp-peer-regression.py /path/to/curl.

Linux can use 127.0.0.2 as the foreign source. On other systems pass a second
local IPv4 address as the optional second argument. No external server is used.
"""
import os
import socket
import subprocess
import sys
import threading
import time


def run_case(binary, foreign, upload=False, ipv6=False):
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    host = "::1" if ipv6 else "127.0.0.1"
    with socket.socket(family, socket.SOCK_DGRAM) as initial, \
            socket.socket(family, socket.SOCK_DGRAM) as peer, \
            socket.socket(family, socket.SOCK_DGRAM) as other:
        initial.bind((host, 0))
        peer.bind((host, 0))
        other.bind((foreign if foreign else host, 0))
        initial.settimeout(4)
        peer.settimeout(4)
        other.settimeout(0.2)
        errors = []
        stolen = []

        def server():
            try:
                request, client = initial.recvfrom(2048)
                assert request[:2] == (b"\0\2" if upload else b"\0\1")
                if foreign:
                    other.sendto(b"\0\4\0\0" if upload else
                                 b"\0\3\0\1forged", client)
                    if upload:
                        try:
                            stolen.append(other.recvfrom(2048)[0])
                        except socket.timeout:
                            pass
                    else:
                        time.sleep(0.2)
                peer.sendto(b"\0\4\0\0" if upload else
                            b"\0\3\0\1correct", client)
                if upload:
                    packet, _ = peer.recvfrom(2048)
                    assert packet == b"\0\3\0\1payload"
                    peer.sendto(b"\0\4\0\1", client)
            except Exception as exc:
                errors.append(exc)

        worker = threading.Thread(target=server, daemon=True)
        worker.start()
        urlhost = "[::1]" if ipv6 else host
        args = [binary, "-sS", "--noproxy", "*", "--max-time", "2",
                "--tftp-no-options", f"tftp://{urlhost}:{initial.getsockname()[1]}/file"]
        if upload:
            args += ["-T", "-"]
        result = subprocess.run(args, input=b"payload" if upload else None,
                                capture_output=True, timeout=4,
                                env=dict(os.environ, NO_PROXY="*"))
        worker.join(4)
        assert not worker.is_alive(), "TFTP test server did not finish"
        assert not errors, errors
        assert result.returncode == 0, result.stderr
        assert not stolen, "upload payload reached the foreign host"
        if not upload:
            assert result.stdout == b"correct", result.stdout
        print(f"PASS {'upload' if upload else 'download'} "
              f"{'IPv6' if ipv6 else 'IPv4'} foreign={bool(foreign)}")


if __name__ == "__main__":
    curl = sys.argv[1]
    attacker = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.2"
    run_case(curl, attacker)
    run_case(curl, attacker, upload=True)
    run_case(curl, None)
    run_case(curl, None, upload=True)
    if socket.has_ipv6:
        run_case(curl, None, ipv6=True)
        run_case(curl, None, upload=True, ipv6=True)
