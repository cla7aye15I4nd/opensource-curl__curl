#!/usr/bin/env python3
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl

"""
Exercise OpenSSL native trust with actual Windows stores and loopback TLS.

Use --allow-store-changes only on a disposable Windows test account. Fresh
certificates are added to CurrentUser CA/ROOT, then removed in finally blocks.
--check-fixtures runs the portable TLS controls without opening Windows stores.
"""

import argparse
import ctypes
import os
import ssl
import subprocess
import tempfile
import threading
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class WindowsStore:
    """Own only the certificate contexts inserted by this test invocation."""

    def __init__(self, name):
        self.api = ctypes.WinDLL("crypt32", use_last_error=True)
        pointer = ctypes.c_void_p
        dword = ctypes.c_uint32
        self.api.CertOpenSystemStoreW.argtypes = [pointer, ctypes.c_wchar_p]
        self.api.CertOpenSystemStoreW.restype = pointer
        self.api.CertAddEncodedCertificateToStore.argtypes = [
            pointer, dword, pointer, dword, dword, ctypes.POINTER(pointer)]
        self.api.CertAddEncodedCertificateToStore.restype = ctypes.c_int
        self.api.CertDeleteCertificateFromStore.argtypes = [pointer]
        self.api.CertDeleteCertificateFromStore.restype = ctypes.c_int
        self.api.CertCloseStore.argtypes = [pointer, dword]
        self.api.CertCloseStore.restype = ctypes.c_int
        # CertOpenSystemStore opens the current user's logical system store,
        # matching the API used by curl's OpenSSL native-CA importer.
        self.handle = self.api.CertOpenSystemStoreW(None, name)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        self.contexts = []

    def add(self, certificate):
        der = ssl.PEM_cert_to_DER_cert(certificate.read_text())
        encoded = ctypes.create_string_buffer(der)
        context = ctypes.c_void_p()
        # X509_ASN_ENCODING=1, CERT_STORE_ADD_NEW=1: never replace an existing
        # certificate, even if a fixture unexpectedly collides with one.
        if not self.api.CertAddEncodedCertificateToStore(
                self.handle, 1, encoded, len(der), 1, ctypes.byref(context)):
            raise ctypes.WinError(ctypes.get_last_error())
        self.contexts.append(context)

    def clear(self):
        errors = []
        while self.contexts:
            # Delete consumes the returned context even when it fails.
            context = self.contexts.pop()
            if not self.api.CertDeleteCertificateFromStore(context):
                errors.append(ctypes.get_last_error())
        if errors:
            raise OSError(f"could not remove test certificates: {errors}")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        try:
            self.clear()
        finally:
            if not self.api.CertCloseStore(self.handle, 0):
                raise ctypes.WinError(ctypes.get_last_error())


def make_certificates(directory, openssl):
    """Create unique roots and a server-auth chain with no network fetches."""
    name = f"curl-native-trust-{uuid.uuid4().hex}"

    def run(*args):
        result = subprocess.run([openssl, *args], check=False, cwd=directory,
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError(f"OpenSSL fixture generation failed:\n{result.stderr}")

    for root in ("root", "unrelated"):
        run("req", "-new", "-newkey", "rsa:2048", "-noenc", "-x509",
            "-days", "2", "-subj", f"/CN={name}-{root}",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", f"{root}.key", "-out", f"{root}.pem")

    for cert, issuer, extensions, serial in (
            ("intermediate", "root",
             ("basicConstraints=critical,CA:TRUE,pathlen:0\n"
              "keyUsage=critical,keyCertSign,cRLSign\n"), "2"),
            ("server", "intermediate",
             ("basicConstraints=critical,CA:FALSE\n"
              "keyUsage=critical,digitalSignature,keyEncipherment\n"
              "extendedKeyUsage=serverAuth\n"
              "subjectAltName=DNS:localhost\n"), "3")):
        subject = "localhost" if cert == "server" else f"{name}-{cert}"
        run("req", "-new", "-newkey", "rsa:2048", "-noenc",
            "-subj", f"/CN={subject}", "-keyout", f"{cert}.key",
            "-out", f"{cert}.csr")
        (directory / f"{cert}.ext").write_text(
            extensions + "subjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid,issuer\n")
        run("x509", "-req", "-in", f"{cert}.csr", "-CA", f"{issuer}.pem",
            "-CAkey", f"{issuer}.key", "-set_serial", serial,
            "-days", "2", "-extfile", f"{cert}.ext", "-out", f"{cert}.pem")

    (directory / "chain.pem").write_bytes(
        (directory / "server.pem").read_bytes() +
        (directory / "intermediate.pem").read_bytes())
    (directory / "empty-ca-path").mkdir()


class Handler(BaseHTTPRequestHandler):
    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, ssl.SSLError):
            # Rejected certificates can close TLS before sending an HTTP request.
            pass

    def do_GET(self):
        body = b"native trust regression\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


@contextmanager
def tls_server(directory, certificate):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(directory / certificate, directory / "server.key")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever,
                              kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("loopback TLS server did not stop")


def check(curl, directory, port, label, expected, ca="unrelated.pem",
          native=False, host="localhost"):
    env = os.environ.copy()
    for key in ("CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR"):
        env.pop(key, None)
    env["CURL_SSL_BACKEND"] = "openssl"
    command = [curl, "--disable", "--silent", "--show-error", "--ipv4",
               "--noproxy", "*", "--proxy", "", "--max-time", "5",
               "--cacert", str(directory / ca),
               "--capath", str(directory / "empty-ca-path"),
               "--ca-native" if native else "--no-ca-native",
               "--resolve", f"{host}:{port}:127.0.0.1",
               f"https://{host}:{port}/"]
    result = subprocess.run(command, check=False, capture_output=True, text=True,
                            timeout=10, env=env)
    if result.returncode != expected:
        raise AssertionError(
            f"{label}: expected curl exit {expected}, got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}")
    if not expected and result.stdout != "native trust regression\n":
        raise AssertionError(f"{label}: transfer did not return the expected body")
    print(f"PASS {label}: curl exit {expected}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--curl", required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--allow-store-changes", action="store_true")
    parser.add_argument("--check-fixtures", action="store_true")
    args = parser.parse_args()
    if not args.check_fixtures:
        if os.name != "nt":
            parser.error("native store tests require native Windows Python")
        if not args.allow_store_changes:
            parser.error("use --allow-store-changes on a disposable Windows account")
    curl = str(Path(args.curl).resolve())
    version = subprocess.run([curl, "--disable", "--version"], check=True,
                             capture_output=True, text=True, timeout=10).stdout
    if "OpenSSL/" not in version:
        parser.error("the curl binary must use the OpenSSL backend")
    print(version, flush=True)
    with tempfile.TemporaryDirectory(prefix="curl-native-trust-") as temporary:
        directory = Path(temporary)
        make_certificates(directory, args.openssl)
        with tls_server(directory, "chain.pem") as full, \
                tls_server(directory, "server.pem") as leaf:
            # Portable controls establish the fixture's signatures, trust,
            # hostname, and missing-intermediate behavior independently.
            check(curl, directory, full, "explicit trusted root", 0, ca="root.pem")
            check(curl, directory, full, "unrelated explicit root", 60)
            check(curl, directory, leaf, "missing intermediate", 60, ca="root.pem")
            check(curl, directory, full, "explicit intermediate anchor", 0,
                  ca="intermediate.pem")
            check(curl, directory, full, "hostname mismatch", 60,
                  ca="root.pem", host="127.0.0.1")
            if args.check_fixtures:
                return
            with WindowsStore("CA") as intermediates, WindowsStore("ROOT") as roots:
                intermediates.add(directory / "intermediate.pem")
                check(curl, directory, full, "CA intermediate is not an anchor", 60,
                      native=True)
                roots.add(directory / "root.pem")
                check(curl, directory, full, "native ROOT and server chain", 0,
                      native=True)
                check(curl, directory, full, "native trust disabled", 60)
                check(curl, directory, leaf, "CA store supplies missing issuer", 0,
                      native=True)
                check(curl, directory, full, "native hostname mismatch", 60,
                      native=True, host="127.0.0.1")
            # Check after cleanup too, so a stale native anchor is observable.
            check(curl, directory, full, "native test root removed", 60, native=True)


if __name__ == "__main__":
    main()
