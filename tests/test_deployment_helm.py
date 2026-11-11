import base64
import copy
import gzip
import json

import pytest
from test_deployment_journal import event, request
from test_deployment_ownership import close, install, slot

from birbverify.contract import digest
from birbverify.deployment_helm import release_content_sha256
from birbverify.deployment_journal import Journal

PRIVATE = "fixture-private-value-do-not-persist"
FAILURE = 'Release "sample" failed: approved test failure'
NAME = "sh.helm.release.v1.sample.v1"


def release(phase="pending-install"):
    return {
        "name": "sample",
        "namespace": "app",
        "version": 1,
        "info": {
            "first_deployed": "2026-11-10T22:00:00.123456789Z",
            "last_deployed": "2026-11-10T22:00:00.123456789Z",
            "deleted": "",
            "description": {
                "pending-install": "Initial install underway",
                "deployed": "Install complete",
                "failed": FAILURE,
            }[phase],
            "status": phase,
            "notes": PRIVATE,
        },
        "config": {"app": PRIVATE},
        "chart": {"metadata": {"name": "sample", "version": "0.1.0"}},
        "manifest": "---\nkind: ConfigMap\n",
    }


def wire(raw):
    return base64.b64encode(base64.b64encode(gzip.compress(raw, mtime=0))).decode()


def storage(payload):
    phase = payload["info"]["status"]
    key = "createdAt" if phase == "pending-install" else "modifiedAt"
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "helm.sh/release.v1",
        "data": {"release": wire(json.dumps(payload).encode())},
        "metadata": {
            "name": NAME,
            "namespace": "app",
            "labels": {
                "owner": "helm",
                "name": "sample",
                "status": phase,
                "version": "1",
                key: "1794354989",
            },
        },
    }


def admission(phase="pending-install"):
    creating = phase == "pending-install"
    req = request(
        uid="pending" if creating else phase, operation="CREATE" if creating else "UPDATE"
    )
    req["resource"]["resource"] = "secrets"
    req["kind"]["kind"] = "Secret"
    req.update(name=NAME, object=storage(release(phase)), oldObject=None)
    if not creating:
        req["oldObject"] = storage(release())
        for obj in (req["object"], req["oldObject"]):
            obj["metadata"].update(uid="object-1", resourceVersion="2")
    return req


def ledger(tmp_path, **changes):
    pin = {
        "release_name": "sample",
        "source_revision": "a" * 40,
        "principal_sha256": digest(request()["userInfo"]),
        "content_sha256": release_content_sha256(release()),
    } | changes
    journal = install(tmp_path / "db", [slot("root", request())], helm_releases=[pin])
    epoch = journal.begin("r", "d" * 64)["epoch"]
    audit = Journal(
        journal.path, journal.installation_sha256, "proof.test", "app", expected_epoch=epoch
    )
    return journal, audit, epoch


def completion(epoch, req):
    result = event(epoch, req)
    result["auditID"] = "audit-" + req["uid"]
    result["objectRef"].update(name=NAME, resource="secrets")
    result["requestObject"] = copy.deepcopy(req["object"])
    for key in ("namespace", "uid", "resourceVersion"):
        result["requestObject"]["metadata"].pop(key, None)
    if req["operation"] == "UPDATE":
        result["responseObject"]["metadata"]["resourceVersion"] = "3"
        result["responseStatus"]["code"] = 200
    return result


def deliver(audit, ev):
    audit.ingest_audit_batch("cluster", "b" * 64, [ev])


@pytest.mark.parametrize("phase", ["deployed", "failed"])
def test_status_requires_settled_incarnation_and_durable_redaction(tmp_path, phase):
    j, audit, epoch = ledger(tmp_path, failed_description_sha256=digest(FAILURE.encode()))
    create, update = admission(), admission(phase)
    assert j.admit(epoch, create)["allowed"]
    assert j.admit(epoch, create)["allowed"]
    assert not j.admit(epoch, update)["allowed"]
    deliver(audit, completion(epoch, create))
    assert not j.admit(epoch, create | {"uid": "again"})["allowed"]
    for k, v in (("uid", "other"), ("resourceVersion", "1")):
        wrong = copy.deepcopy(update)
        for obj in (wrong["oldObject"], wrong["object"]):
            obj["metadata"][k] = v
        assert not j.admit(epoch, wrong)["allowed"]
    assert j.admit(epoch, update)["allowed"]
    assert not j.admit(epoch, update | {"uid": "again"})["allowed"]
    assert [e["state"] for e in close(j, epoch, "completed")["effects"]] == ["settled", "pending"]
    ev = completion(epoch, update)
    deliver(audit, ev)
    deliver(audit, ev)
    report = close(j, epoch, "completed")
    assert [(e["slot"], e["object_uid"], e["state"]) for e in report["effects"]] == [
        ("helm-sample-create", "object-1", "settled"),
        ("helm-sample-status", "object-1", "settled"),
    ]
    assert not report["release_authorized"]
    for path in tmp_path.iterdir():
        raw = path.read_bytes()
        for secret in (
            PRIVATE,
            create["object"]["data"]["release"],
            update["object"]["data"]["release"],
            FAILURE,
        ):
            assert secret.encode() not in raw


@pytest.mark.parametrize(
    "change",
    [
        lambda req: req["object"].update(type="Opaque"),
        lambda req: req["object"]["metadata"].update(annotations={"test": PRIVATE}),
        lambda req: req["object"]["data"].update(unreviewed=PRIVATE),
        lambda req: req["object"]["metadata"]["labels"].update(status="deployed"),
        lambda req: req["object"]["data"].update(release=wire(b" " * (4 * 1024 * 1024 + 1))),
        lambda req: req["object"]["data"].update(release=wire(b'{"name":"sample","name":"other"}')),
        lambda req: req["object"]["data"].update(release="invalid"),
        lambda req: req.update(userInfo={"username": "other"}),
        lambda req: req.update(requestResource={"group": "", "version": "v1", "resource": "pods"}),
        lambda req: req.update(subResource="status"),
        lambda req: req.update(operation="DELETE"),
        lambda req: req.update(name="sh.helm.release.v1.sample.v2"),
    ],
)
def test_denies_unsupported_storage_without_recording_an_intent(tmp_path, change):
    j, _, epoch = ledger(tmp_path)
    create = admission()
    change(create)
    assert not j.admit(epoch, create)["allowed"]
    assert not j.snapshot(epoch)["intents"]


@pytest.mark.parametrize("field", ["chart", "config", "manifest", "hooks", "notes", "version"])
def test_installation_pins_entire_rendered_release(tmp_path, field):
    j, _, epoch = ledger(tmp_path)
    payload = release()
    if field == "notes":
        payload["info"]["notes"] += "!"
    else:
        payload[field] = {"changed": True}
    assert not j.admit(epoch, admission() | {"object": storage(payload)})["allowed"]


def test_failed_status_and_conflicting_authenticated_replay(tmp_path):
    j, audit, epoch = ledger(tmp_path)
    create = admission()
    assert j.admit(epoch, create)["allowed"]
    deliver(audit, completion(epoch, create))
    assert not j.admit(epoch, admission("failed"))["allowed"]
    update = admission("deployed")
    assert j.admit(epoch, update)["allowed"]
    ev = completion(epoch, update)
    ev["responseObject"]["metadata"]["labels"]["modifiedAt"] = "1794354990"
    deliver(audit, ev)
    assert audit.snapshot(epoch)["quarantined"] == ["deployed"]
    assert PRIVATE.encode() not in j.path.read_bytes()


@pytest.mark.parametrize("operation", ["CREATE", "UPDATE"])
@pytest.mark.parametrize("change", ["missing", "wrong-content", "wrong-namespace"])
def test_inconsistent_submitted_secret_quarantines_completion(tmp_path, operation, change):
    journal, audit, epoch = ledger(tmp_path)
    req = admission()
    assert journal.admit(epoch, req)["allowed"]
    if operation == "UPDATE":
        deliver(audit, completion(epoch, req))
        req = admission("deployed")
        assert journal.admit(epoch, req)["allowed"]
    ev = completion(epoch, req)
    if change == "missing":
        del ev["requestObject"]
    elif change == "wrong-content":
        ev["requestObject"]["data"] = {"unknown": PRIVATE}
    else:
        ev["requestObject"]["metadata"]["namespace"] = "other"
    deliver(audit, ev)
    assert journal.snapshot(epoch)["state"] == "quarantined"
    assert PRIVATE.encode() not in journal.path.read_bytes()
