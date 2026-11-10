import copy
import stat
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from birbverify.deployment_journal import Journal


def request(uid="review-1", operation="CREATE"):
    obj = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "config", "namespace": "app"},
        "data": {"value": "accepted"},
    }
    if operation != "CREATE":
        obj["metadata"].update(uid="object-1", resourceVersion="1")
    return {
        "uid": uid,
        "operation": operation,
        "dryRun": False,
        "namespace": "app",
        "name": "config",
        "userInfo": {"username": "controller"},
        "resource": {"group": "", "version": "v1", "resource": "configmaps"},
        "kind": {"group": "", "version": "v1", "kind": "ConfigMap"},
        "object": obj if operation != "DELETE" else None,
        "oldObject": obj if operation != "CREATE" else None,
        "options": {"preconditions": {"uid": "object-1"}} if operation == "DELETE" else {},
    }


def event(epoch, req=None):
    req = req or request()
    obj = copy.deepcopy(req["object"] or req["oldObject"])
    obj["metadata"].update(uid="object-1", resourceVersion="2")
    return {
        "apiVersion": "audit.k8s.io/v1",
        "kind": "Event",
        "level": "RequestResponse",
        "stage": "ResponseComplete",
        "auditID": "api-1",
        "verb": req["operation"].lower(),
        "user": req["userInfo"],
        "objectRef": {
            "apiVersion": "v1",
            "resource": "configmaps",
            "name": "config",
            "namespace": "app",
        },
        "responseStatus": {"code": 201},
        "responseObject": obj,
        "annotations": {"proof.test/intent-" + req["uid"]: epoch},
    }


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "private" / "ledger.sqlite", "a" * 64, "proof.test", "app")


def begin(journal):
    return journal.begin("request-1", "b" * 64)["epoch"]


def test_restart_preserves_pending_and_sealed_completion(journal):
    epoch = begin(journal)
    allowed = journal.admit(epoch, request())
    assert allowed["allowed"]
    assert allowed["auditAnnotations"] == {"intent-review-1": epoch}
    restarted = Journal(journal.path, "a" * 64, "proof.test", "app")
    assert restarted.snapshot(epoch)["pending"] == ["review-1"]
    assert restarted.begin("request-1", "b" * 64)["epoch"] == epoch
    restarted.seal(epoch)
    assert not journal.admit(epoch, request())["allowed"]
    assert not journal.admit(epoch, request("review-2"))["allowed"]
    result = journal.ingest(event(epoch))
    assert result["state"] == "sealed"
    assert result["settled"] == ["review-1"]
    assert result["pending"] == []
    assert result["intents"][0]["evidence"]["object_uid"] == "object-1"
    assert result["intents"][0]["evidence"]["termination_proven"] is False
    assert journal.ingest(event(epoch)) == result
    assert stat.S_IMODE(journal.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(journal.path.parent.stat().st_mode) == 0o700


@pytest.mark.parametrize(
    "change",
    [
        lambda e: e.update(apiVersion="audit.k8s.io/v2"),
        lambda e: e.update(stage="ResponseStarted"),
        lambda e: e.update(level="Metadata"),
        lambda e: e.update(user={"username": "other"}),
        lambda e: e.update(impersonatedUser={"username": "other"}),
        lambda e: e.update(verb="delete"),
        lambda e: e["objectRef"].update(apiVersion="v2"),
        lambda e: e["objectRef"].update(namespace="other"),
        lambda e: e["objectRef"].update(name="other"),
        lambda e: e["objectRef"].update(subresource="status"),
        lambda e: e["responseStatus"].update(code=504),
        lambda e: e["responseStatus"].update(code=409),
        lambda e: e["responseObject"]["data"].update(value="changed"),
        lambda e: e["responseObject"]["metadata"].update(name="other"),
        lambda e: e["responseObject"]["metadata"].pop("uid"),
        lambda e: e["annotations"].update({"proof.test/intent-review-1": "wrong-epoch"}),
        lambda e: e["annotations"].update({"proof.test/intent-other": "other"}),
    ],
)
def test_mismatched_completion_quarantines(journal, change):
    epoch = begin(journal)
    journal.admit(epoch, request())
    completion = event(epoch)
    change(completion)
    result = journal.ingest(completion)
    assert result["settled"] == []
    assert result["quarantined"] == ["review-1"]
    assert result["state"] == "quarantined"
    assert not journal.admit(epoch, request("later"))["allowed"]
    assert journal.seal(epoch)["state"] == "quarantined"
    assert journal.ingest(event(epoch))["quarantined"] == ["review-1"]


def test_uncorrelated_events_never_settle(journal):
    epoch = begin(journal)
    journal.admit(epoch, request())
    completion = event(epoch)
    completion["annotations"] = {"other.test/intent-review-1": epoch}
    assert journal.ingest(completion) is None
    assert journal.snapshot(epoch)["pending"] == ["review-1"]
    completion["annotations"] = {"proof.test/intent-unknown": epoch}
    result = journal.ingest(completion)
    assert result["pending"] == ["review-1"]
    assert result["state"] == "quarantined"
    assert not journal.admit(epoch, request("later"))["allowed"]


def test_conflicting_replay_quarantines(journal):
    epoch = begin(journal)
    journal.admit(epoch, request())
    assert journal.ingest(event(epoch))["settled"]
    conflicting = event(epoch)
    conflicting["auditID"] = "different"
    assert journal.ingest(conflicting)["quarantined"] == ["review-1"]


def test_admission_uid_reuse_and_replay(journal):
    epoch = begin(journal)
    assert journal.admit(epoch, request()) == journal.admit(epoch, request())
    changed = request()
    changed["object"]["data"]["value"] = "changed"
    assert not journal.admit(epoch, changed)["allowed"]
    assert not journal.admit(epoch, request())["allowed"]
    assert journal.snapshot(epoch)["quarantined"] == ["review-1"]


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r.update(dryRun=True),
        lambda r: r.update(operation="CONNECT"),
        lambda r: r.update(namespace="other"),
        lambda r: r.update(subResource="status"),
        lambda r: r["object"].update(kind="Secret"),
        lambda r: r["object"]["metadata"].update(name="other"),
    ],
)
def test_admission_denial_leaves_no_intent(journal, change):
    epoch = begin(journal)
    req = request()
    change(req)
    assert not journal.admit(epoch, req)["allowed"]
    assert journal.snapshot(epoch)["intents"] == []


def test_delete_requires_uid_and_never_proves_termination(journal):
    epoch = begin(journal)
    req = request(operation="DELETE")
    wrong = copy.deepcopy(req)
    wrong["options"] = {}
    assert not journal.admit(epoch, wrong)["allowed"]
    assert journal.admit(epoch, req)["allowed"]
    completion = event(epoch, req)
    completion["responseObject"] = {
        "apiVersion": "v1",
        "kind": "Status",
        "status": "Success",
        "details": {"uid": "object-1", "name": "config", "kind": "configmaps"},
    }
    result = journal.ingest(completion)
    assert result["settled"] == ["review-1"]
    assert result["intents"][0]["evidence"]["termination_proven"] is False


def test_update_patch_and_impersonation(journal):
    epoch = begin(journal)
    req = request(operation="UPDATE")
    assert journal.admit(epoch, req)["allowed"]
    completion = event(epoch, req)
    completion.update(verb="patch", user={"username": "admin"}, impersonatedUser=req["userInfo"])
    assert journal.ingest(completion)["settled"] == ["review-1"]


def test_two_owners_serialize_seal_and_admission(journal):
    epoch = begin(journal)
    other = Journal(journal.path, "a" * 64, "proof.test", "app")
    barrier = Barrier(2)

    def admit():
        barrier.wait()
        return journal.admit(epoch, request())

    def seal():
        barrier.wait()
        return other.seal(epoch)

    with ThreadPoolExecutor(max_workers=2) as pool:
        admission = pool.submit(admit)
        sealing = pool.submit(seal)
        accepted = admission.result()["allowed"]
        sealed = sealing.result()
    assert bool(sealed["pending"]) == accepted
    assert journal.snapshot(epoch)["state"] == "sealed"
    assert not other.admit(epoch, request("after"))["allowed"]


def test_installation_and_request_identity_cannot_change(journal):
    begin(journal)
    with pytest.raises(ValueError):
        Journal(journal.path, "c" * 64, "proof.test", "app")
    with pytest.raises(ValueError):
        journal.begin("other", "b" * 64)
    with pytest.raises(ValueError):
        journal.begin("request-1", "c" * 64)


def test_two_owners_cannot_begin_different_epochs(journal):
    other = Journal(journal.path, "a" * 64, "proof.test", "app")
    barrier = Barrier(2)

    def start(owner, name):
        barrier.wait()
        try:
            return owner.begin(name, "b" * 64)
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(start, journal, "first")
        second = pool.submit(start, other, "second")
        results = [first.result(), second.result()]
    assert sum(result is not None for result in results) == 1


def test_changed_existing_uid_does_not_settle(journal):
    epoch = begin(journal)
    req = request(operation="UPDATE")
    journal.admit(epoch, req)
    completion = event(epoch, req)
    completion["responseObject"]["metadata"]["uid"] = "replacement"
    assert journal.ingest(completion)["quarantined"] == ["review-1"]


def test_server_metadata_and_status_can_be_added(journal):
    epoch = begin(journal)
    journal.admit(epoch, request())
    completion = event(epoch)
    completion["responseObject"]["metadata"].update(
        creationTimestamp="2026-11-10T00:00:00Z", managedFields=[], generation=1
    )
    completion["responseObject"]["status"] = {}
    assert journal.ingest(completion)["settled"] == ["review-1"]


def test_quarantined_state_survives_restart(journal):
    epoch = begin(journal)
    journal.admit(epoch, request())
    completion = event(epoch)
    completion["responseStatus"]["code"] = 504
    journal.ingest(completion)
    restarted = Journal(journal.path, "a" * 64, "proof.test", "app")
    assert restarted.snapshot(epoch)["state"] == "quarantined"
    assert not restarted.admit(epoch, request("new"))["allowed"]
    assert restarted.ingest(event(epoch))["quarantined"] == ["review-1"]


def test_unknown_audit_intent_quarantines_empty_sealed_epoch(journal):
    epoch = begin(journal)
    journal.seal(epoch)
    result = journal.ingest(event(epoch))
    assert result["state"] == "quarantined"
    assert result["settled"] == []
    assert result["reason"] == "audit intent absent from journal"
    assert journal.seal(epoch)["state"] == "quarantined"


def test_audit_identity_cannot_settle_different_intents_after_restart(journal):
    epoch = begin(journal)
    first, second = request(), request("review-2")
    journal.admit(epoch, first)
    journal.admit(epoch, second)
    assert journal.ingest(event(epoch, first))["settled"] == ["review-1"]
    restarted = Journal(journal.path, "a" * 64, "proof.test", "app")
    result = restarted.ingest(event(epoch, second))
    assert result["state"] == "quarantined"
    assert result["settled"] == []
    assert result["quarantined"] == ["review-1", "review-2"]
    assert not restarted.admit(epoch, request("later"))["allowed"]


def generated_create(epoch):
    req = request()
    req["object"]["metadata"].update(name="config-abc", generateName="config-")
    req["name"] = "config-abc"
    completion = event(epoch, req)
    completion["objectRef"].pop("name")
    completion["requestObject"] = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"generateName": "config-"},
    }
    return req, completion


def test_generated_name_create_settles_with_collection_audit_reference(journal):
    epoch = begin(journal)
    req, completion = generated_create(epoch)
    assert journal.admit(epoch, req)["allowed"]
    journal.seal(epoch)
    result = journal.ingest(completion)
    assert result["settled"] == ["review-1"]
    assert result["state"] == "sealed"


@pytest.mark.parametrize(
    "change",
    [
        lambda e: e["objectRef"].update(name="other"),
        lambda e: e["objectRef"].update(name=""),
        lambda e: e["requestObject"]["metadata"].update(generateName="other-"),
        lambda e: e["requestObject"]["metadata"].update(name="config-abc"),
        lambda e: e["requestObject"]["metadata"].update(namespace="other"),
        lambda e: e["requestObject"].update(kind="Pod"),
        lambda e: e["requestObject"].update(apiVersion="v2"),
        lambda e: e.pop("requestObject"),
        lambda e: e["responseObject"]["metadata"].update(name="config-other"),
    ],
)
def test_generated_name_create_requires_provenance_and_exact_response(journal, change):
    epoch = begin(journal)
    req, completion = generated_create(epoch)
    journal.admit(epoch, req)
    change(completion)
    assert journal.ingest(completion)["state"] == "quarantined"


def test_named_create_still_requires_named_audit_reference(journal):
    epoch = begin(journal)
    journal.admit(epoch, request())
    completion = event(epoch)
    completion["objectRef"].pop("name")
    assert journal.ingest(completion)["state"] == "quarantined"
