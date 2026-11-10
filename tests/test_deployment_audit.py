import hashlib
import http.client
import json
import ssl
import subprocess
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest
from test_deployment_journal import begin, event, request

from birbverify import deployment_journal
from birbverify.deployment_audit import AuditReceiver
from birbverify.deployment_journal import Journal

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    root = tmp_path_factory.mktemp("audit-pki")
    subprocess.run(
        [sys.executable, str(ROOT / "fixtures/deployment_audit_pki.py"), str(root), "localhost"],
        check=True,
    )
    return root


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal.sqlite", "a" * 64, "proof.test", "app")


@contextmanager
def listening(journal, pki):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(pki / "server.crt", pki / "server.key")
    context.load_verify_locations(cafile=pki / "ca.crt")
    pin = (pki / "pin").read_text()
    journal.bind_audit_source("cluster-1", pin)
    with AuditReceiver(("localhost", 0), journal, "cluster-1", pin, context) as server:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            yield server.server_port
        finally:
            server.shutdown()
            thread.join()


def post(port, pki, payload, client="apiserver"):
    context = ssl.create_default_context(cafile=pki / "ca.crt")
    if client is not None:
        context.load_cert_chain(pki / (client + ".crt"), pki / (client + ".key"))
    connection = http.client.HTTPSConnection("localhost", port, context=context, timeout=5)
    try:
        body = (
            payload
            if isinstance(payload, bytes)
            else json.dumps(
                {
                    "apiVersion": "audit.k8s.io/v1",
                    "kind": "EventList",
                    "items": payload,
                }
            ).encode()
        )
        connection.request(
            "POST", "/v1/audit", body=body, headers={"Content-Type": "application/json"}
        )
        return connection.getresponse().status
    finally:
        connection.close()


def test_only_pinned_client_settles_after_restart(journal, pki):
    epoch = begin(journal)
    completion = event(epoch)
    del completion["kind"], completion["apiVersion"]
    with listening(journal, pki) as port:
        assert journal.admit(epoch, request())["allowed"]
        journal.seal(epoch)
        assert post(port, pki, [completion], "unassigned") == 403
        with pytest.raises((ssl.SSLError, ConnectionError)):
            post(port, pki, [completion], None)
        with pytest.raises(ValueError, match="authenticated"):
            journal.ingest(event(epoch))
        assert journal.snapshot(epoch)["pending"] == ["review-1"]
        assert post(port, pki, [completion]) == 200
        settled = journal.snapshot(epoch)
        assert settled["settled"] == ["review-1"]
        assert settled["intents"][0]["evidence"]["object_uid"] == "object-1"

    restarted = Journal(journal.path, "a" * 64, "proof.test", "app")
    with listening(restarted, pki) as port:
        assert post(port, pki, [completion]) == 200
        assert restarted.snapshot(epoch) == settled
        changed = event(epoch)
        changed["responseObject"]["metadata"]["uid"] = "other"
        assert post(port, pki, [changed]) == 200
        assert restarted.snapshot(epoch)["state"] == "quarantined"


def test_rejects_ambiguous_batch_and_wrong_installation(journal, pki):
    with listening(journal, pki) as port:
        epoch = begin(journal)
        assert journal.admit(epoch, request())["allowed"]
        assert post(port, pki, [event(epoch), None]) == 400
        assert post(port, pki, b'{"kind":"Event","kind":"EventList","items":[]}') == 400
        assert journal.snapshot(epoch)["pending"] == ["review-1"]
        with pytest.raises(ValueError, match="source already pinned"):
            journal.bind_audit_source("cluster-2", (pki / "pin").read_text())
        with pytest.raises(ValueError, match="source already pinned"):
            journal.bind_audit_source("cluster-1", hashlib.sha256(b"other").hexdigest())


def test_receiver_cannot_adopt_old_evidence(journal, pki):
    epoch = begin(journal)
    journal.admit(epoch, request())
    journal.ingest(event(epoch))
    with pytest.raises(ValueError, match="existing proof journal"), listening(journal, pki):
        pass


def test_capacity_retains_old_evidence(journal, pki, monkeypatch):
    monkeypatch.setattr(deployment_journal, "MAX_INTENTS", 1)
    monkeypatch.setattr(deployment_journal, "MAX_AUDIT_EVENTS", 1)
    with listening(journal, pki) as port:
        epoch = begin(journal)
        assert journal.admit(epoch, request())["allowed"]
        assert not journal.admit(epoch, request("second"))["allowed"]
        assert post(port, pki, [event(epoch)]) == 200
        assert post(port, pki, [event(epoch)]) == 200
        assert journal.snapshot(epoch)["settled"] == ["review-1"]
        changed = event(epoch)
        changed["auditID"] = "other"
        assert post(port, pki, [changed]) == 200
        assert journal.snapshot(epoch)["state"] == "quarantined"


def test_impersonated_completion_quarantines_bound_journal(journal, pki):
    with listening(journal, pki) as port:
        epoch = begin(journal)
        assert journal.admit(epoch, request())["allowed"]
        completion = event(epoch)
        completion.update(impersonatedUser=completion["user"])
        assert post(port, pki, [completion]) == 200
        snapshot = journal.snapshot(epoch)
        assert snapshot["state"] == "quarantined" and not snapshot["settled"]
