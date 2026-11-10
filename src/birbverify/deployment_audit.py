"""Authenticated Kubernetes audit.k8s.io/v1 EventList receiver."""

import argparse
import sqlite3
from urllib.parse import urlsplit

from birbverify.deployment_http import HttpError, JSONHandler, MutualTLSServer, server_context
from birbverify.deployment_journal import Journal

MAX_BATCH_BYTES = 4 * 1024 * 1024
MAX_BATCH_EVENTS = 128


def batch_events(envelope):
    if not isinstance(envelope, dict) or (envelope.get("kind"), envelope.get("apiVersion")) != (
        "EventList",
        "audit.k8s.io/v1",
    ):
        raise ValueError("expected audit.k8s.io/v1 EventList")
    events = envelope.get("items")
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_BATCH_EVENTS:
        raise ValueError("invalid audit batch size")
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("invalid event")
        # Kubernetes may omit TypeMeta on items in a typed EventList.
        event.setdefault("kind", "Event")
        event.setdefault("apiVersion", "audit.k8s.io/v1")
    return events


class AuditHandler(JSONHandler):
    def do_POST(self):
        if urlsplit(self.path).path.rstrip("/") != "/v1/audit":
            return self.reply(404)
        fingerprint = self.client_sha256()
        if fingerprint != self.server.client_cert_sha256:
            return self.reply(403)
        try:
            events = batch_events(self.body(MAX_BATCH_BYTES))
            self.server.journal.ingest_audit_batch(self.server.cluster_uid, fingerprint, events)
        except HttpError as error:
            return self.reply(error.status)
        except (ValueError, RecursionError):
            return self.reply(400)
        except sqlite3.Error:
            return self.reply(503)
        self.reply(200)


class AuditReceiver(MutualTLSServer):
    def __init__(self, address, journal, cluster_uid, client_cert_sha256, tls):
        self.journal = journal
        self.cluster_uid = cluster_uid
        self.client_cert_sha256 = client_cert_sha256
        journal.require_audit_source(cluster_uid, client_cert_sha256)
        super().__init__(address, AuditHandler, tls)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "journal",
        "installation-sha256",
        "webhook-name",
        "namespace",
        "cluster-uid",
        "epoch",
        "client-cert-sha256",
        "client-ca",
        "server-cert",
        "server-key",
    ):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    tls = server_context(args.client_ca, args.server_cert, args.server_key)
    journal = Journal(
        args.journal,
        args.installation_sha256,
        args.webhook_name,
        args.namespace,
        expected_epoch=args.epoch,
    )
    with AuditReceiver(
        (args.host, args.port), journal, args.cluster_uid, args.client_cert_sha256, tls
    ) as receiver:
        receiver.serve_forever()


if __name__ == "__main__":
    main()
