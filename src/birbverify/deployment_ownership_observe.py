"""Record a terminal Kubernetes status for one settled Pod during closure."""

import argparse
import json
import re
from datetime import datetime
from pathlib import Path

from birbverify.contract import digest
from birbverify.deployment_ownership import OwnershipJournal, OwnershipPolicy
from birbverify.kubernetes_api import KubernetesAPI

_CONTAINER_ID = re.compile(r"(?:containerd|cri-o)://[a-f0-9]{64}")


def _containers(admitted, current, status_list):
    expected = {c["name"]: c["image"] for c in admitted}
    live = {c["name"]: c["image"] for c in current}
    statuses = {c["name"]: c for c in status_list}
    if (
        len(expected) != len(admitted)
        or len(live) != len(current)
        or len(statuses) != len(status_list)
        or live != expected
        or statuses.keys() != expected.keys()
    ):
        raise ValueError("terminal container inventory mismatch")
    result = {}
    for name, value in statuses.items():
        state = value["state"]
        if set(state) != {"terminated"}:
            raise ValueError("container termination unobserved")
        term = state["terminated"]
        cid = term.get("containerID")
        if (
            not isinstance(cid, str)
            or not _CONTAINER_ID.fullmatch(cid)
            or value.get("containerID") != cid
            or type(term.get("exitCode")) is not int
        ):
            raise ValueError("container termination identity mismatch")
        started = datetime.fromisoformat(term["startedAt"])
        finished = datetime.fromisoformat(term["finishedAt"])
        if not started.tzinfo or not finished.tzinfo or finished < started:
            raise ValueError("container termination time mismatch")
        result[name] = {
            "container_id": cid,
            "exit_code": term["exitCode"],
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "image": expected[name],
        }
    return result


def _settled_pod(db, journal, epoch, slot):
    row = journal._epoch(db, epoch)
    if row["state"] != "sealed":
        raise ValueError("epoch must be sealed")
    saved = db.execute(
        "SELECT data FROM ownership_slots JOIN intents ON uid=review_uid WHERE slot=?", (slot,)
    ).fetchone()
    if not saved:
        raise ValueError("unowned slot")
    intent = json.loads(saved[0])
    if intent["state"] != "settled" or intent["request"]["object"]["kind"] != "Pod":
        raise ValueError("settled Pod required")
    return intent


def observe_terminal(journal, epoch, slot, api):
    policy = journal.policy
    pin = policy.terminal_observer
    if pin is None:
        raise ValueError("terminal observer not installed")
    with journal._transaction() as db:
        intent = _settled_pod(db, journal, epoch, slot)
        existing = db.execute("SELECT digest FROM terminal_status WHERE slot=?", (slot,)).fetchone()
        if existing:
            return existing[0]
    for name, uid in (
        ("kube-system", policy.cluster_uid),
        (policy.namespace, policy.namespace_uid),
    ):
        ns = api.request("GET", f"/api/v1/namespaces/{name}")["metadata"]
        if ns.get("name") != name or ns.get("uid") != uid or ns.get("deletionTimestamp"):
            raise ValueError("namespace incarnation mismatch")
    node = api.request("GET", f"/api/v1/nodes/{pin.node_name}")
    if (
        node["metadata"].get("name") != pin.node_name
        or node["metadata"].get("uid") != pin.node_uid
        or node["metadata"].get("deletionTimestamp")
        or [c.get("status") for c in node["status"]["conditions"] if c.get("type") == "Ready"]
        != ["True"]
    ):
        raise ValueError("node incarnation unavailable")
    admitted = intent["request"]["object"]
    name = admitted["metadata"]["name"]
    pod = api.request("GET", f"/api/v1/namespaces/{policy.namespace}/pods/{name}")
    metadata, spec, status = pod["metadata"], pod["spec"], pod["status"]
    uid = intent["evidence"]["object_uid"]
    if (
        pod.get("kind") != "Pod"
        or pod.get("apiVersion") != "v1"
        or (metadata.get("name"), metadata.get("namespace"), metadata.get("uid"))
        != (name, policy.namespace, uid)
        or not metadata.get("resourceVersion")
        or spec.get("nodeName") != pin.node_name
        or spec.get("ephemeralContainers")
        or status.get("ephemeralContainerStatuses")
        or status.get("phase") not in ("Succeeded", "Failed")
    ):
        raise ValueError("terminal Pod incarnation mismatch")
    obs = {
        "uid": uid,
        "resource_version": metadata["resourceVersion"],
        "node_uid": pin.node_uid,
        "phase": status["phase"],
        "intent_uid": intent["uid"],
    }
    for section, status_key in (
        ("containers", "containerStatuses"),
        ("initContainers", "initContainerStatuses"),
    ):
        obs[section] = _containers(
            admitted["spec"].get(section, []), spec.get(section, []), status.get(status_key, [])
        )
    with journal._transaction() as db:
        _settled_pod(db, journal, epoch, slot)
        db.execute(
            "INSERT OR IGNORE INTO terminal_status VALUES (?,?,?)",
            (slot, digest(obs), json.dumps(obs, sort_keys=True, separators=(",", ":"))),
        )
        return db.execute("SELECT digest FROM terminal_status WHERE slot=?", (slot,)).fetchone()[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("journal", "policy", "epoch", "slot", "kubeconfig"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    policy = OwnershipPolicy.model_validate_json(Path(args.policy).read_bytes())
    pin = policy.terminal_observer
    config = Path(args.kubeconfig)
    if pin is None or digest(config.read_bytes()) != pin.kubeconfig_sha256:
        parser.error("terminal observer kubeconfig pin mismatch")
    journal = OwnershipJournal(args.journal, policy, expected_epoch=args.epoch)
    print(observe_terminal(journal, args.epoch, args.slot, KubernetesAPI(config, pin.context)))


if __name__ == "__main__":
    main()
