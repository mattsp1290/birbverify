"""Mutual TLS and bounded JSON framing used by deployment services."""

import hashlib
import json
import re
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer


def server_context(client_ca, server_cert, server_key):
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.verify_mode = ssl.CERT_REQUIRED
    tls.load_verify_locations(cafile=client_ca)
    tls.load_cert_chain(server_cert, server_key)
    return tls


class MutualTLSServer(HTTPServer):
    def __init__(self, address, handler_cls, tls):
        if tls.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError("client authentication required")
        self.tls = tls
        super().__init__(address, handler_cls)

    def get_request(self):
        client, address = super().get_request()
        try:
            client.settimeout(5)
            return self.tls.wrap_socket(client, server_side=True), address
        except BaseException:
            client.close()
            raise


class HttpError(ValueError):
    def __init__(self, status):
        self.status = status
        super().__init__(f"HTTP {status}")


def unique_keys(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("duplicate JSON key")
    return value


def _nonfinite(_):
    raise ValueError("nonfinite JSON number")


def strict_json(raw):
    return json.loads(raw, object_pairs_hook=unique_keys, parse_constant=_nonfinite)


class JSONHandler(BaseHTTPRequestHandler):
    def client_sha256(self):
        return hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()

    def body(self, max_bytes):
        if self.headers.get_content_type() != "application/json":
            raise HttpError(415)
        lengths = self.headers.get_all("Content-Length", [])
        if (
            self.headers.get("Transfer-Encoding") is not None
            or len(lengths) != 1
            or not re.fullmatch("[0-9]{1,10}", lengths[0])
        ):
            raise HttpError(400)
        size = int(lengths[0])
        if not 1 <= size <= max_bytes:
            raise HttpError(413)
        raw = self.rfile.read(size)
        if len(raw) != size:
            raise HttpError(400)
        return strict_json(raw)

    def reply(self, status, result=None):
        body = b"" if result is None else json.dumps(result, allow_nan=False).encode()
        self.send_response_only(status)
        self.send_header("Content-Length", str(len(body)))
        if body:
            self.send_header("Content-Type", "application/json")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, *_args):
        pass
