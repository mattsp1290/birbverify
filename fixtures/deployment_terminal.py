"""Prove terminal observation of one real Helm hook before its Pod is cleaned up."""

import json
import os
import sqlite3
from contextlib import closing
from functools import partial
from pathlib import Path

import yaml

from birbverify.contract import digest
from birbverify.deployment_ownership import object_shape_sha256

FIXTURE = Path(__file__).parent / "terminal-hook"
TARGET, CONTROL, POD = "proof-target", "proof-control", "terminal-hook"


def configure(root, kubectl, node_name, fixture):
    for ns in (CONTROL, TARGET):
        kubectl("create", "namespace", ns)
    user = fixture.release_identity(root, kubectl)
    for ns, resources, verbs in (
        (CONTROL, "secrets", "create,get,list,update"),
        (TARGET, "pods", "create,get,list,watch,delete"),
    ):
        kubectl("-n", ns, "create", "role", "helm", "--resource", resources, "--verb", verbs)
        kubectl(
            "-n", ns, "create", "rolebinding", "helm", "--role=helm", "--user", user["username"]
        )

    observer = "terminal-observer"
    kubectl("-n", CONTROL, "create", "serviceaccount", observer)
    subject = f"--serviceaccount={CONTROL}:{observer}"
    kubectl(
        "-n",
        TARGET,
        "create",
        "role",
        observer,
        "--resource=pods",
        "--resource-name",
        POD,
        "--verb=get",
    )
    kubectl("-n", TARGET, "create", "rolebinding", observer, "--role", observer, subject)
    for resource, names in [("nodes", [node_name]), ("namespaces", ["kube-system", TARGET])]:
        role = observer + "-" + resource
        kubectl(
            "create",
            "clusterrole",
            role,
            "--verb=get",
            "--resource",
            resource,
            *["--resource-name=" + name for name in names],
        )
        kubectl("create", "clusterrolebinding", role, "--clusterrole", role, subject)
    cluster = yaml.safe_load((root / "kubeconfig").read_text())["clusters"][0]["cluster"]
    observer_config = root / "observer.kubeconfig"
    token = kubectl("-n", CONTROL, "create", "token", observer, "--duration=15m")
    fixture.write(
        observer_config,
        fixture.config(cluster["server"], cluster["certificate-authority-data"], {"token": token}),
    )
    rendered = fixture.run("helm", "template", POD, FIXTURE / "chart", "--namespace", CONTROL)
    # Use the API server's CREATE defaults before enrolling the finite slot.
    pod = json.loads(kubectl("create", "--dry-run=server", "-o", "json", "-f", "-", data=rendered))

    def uid(resource):
        return kubectl("get", resource, "-o", "jsonpath={.metadata.uid}")

    pin = fixture.pin
    return dict(
        schema_version="birbverify.deployment.ownership.v1",
        cluster_uid=uid("namespace/kube-system"),
        namespace=TARGET,
        namespace_uid=uid("namespace/" + TARGET),
        webhook_name=fixture.WEBHOOK,
        audit_client_sha256=pin(root / "audit/apiserver.crt"),
        admission_client_sha256=pin(root / "admission/apiserver.crt"),
        closure_client_sha256=pin(root / "admission/unassigned.crt"),
        terminal_observer=dict(
            node_name=node_name,
            node_uid=uid("node/" + node_name),
            context="proof",
            kubeconfig_sha256=digest(observer_config.read_bytes()),
        ),
        rules=[
            dict(
                slot=POD,
                name=POD,
                kind="Pod",
                principal_sha256=digest(user),
                object_sha256=object_shape_sha256(pod, generated=False, owned=False),
            )
        ],
    )


def exercise(root, cluster, stack, image, fixture):
    run, write = fixture.run, fixture.write
    kubectl = partial(run, "kubectl", "--kubeconfig", root / "kubeconfig")
    policy = configure(root, kubectl, cluster + "-control-plane", fixture)
    write(root / "policy.json", policy)
    request_sha = digest({"fixture": POD, "policy": digest(policy)})
    container = partial(fixture.start_container, cluster, stack, image)
    server = fixture.start_services(root, policy, request_sha, container)
    guard = fixture.guard_installation(
        root,
        cluster,
        kubectl,
        server,
        TARGET,
        rules=[
            dict(
                apiGroups=[""],
                apiVersions=["v1"],
                resources=["pods"],
                operations=["CREATE"],
                scope="Namespaced",
            )
        ],
    )
    release = json.loads(
        run(
            "helm",
            "install",
            "-o",
            "json",
            "--kubeconfig",
            root / "release.kubeconfig",
            "--namespace",
            CONTROL,
            "--timeout=120s",
            POD,
            FIXTURE / "chart",
        )
    )
    [hook] = release["hooks"]
    assert (release["name"], release["namespace"], release["info"]["status"]) == (
        POD,
        CONTROL,
        "deployed",
    )
    assert (hook["kind"], hook["events"], hook["last_run"]["phase"]) == (
        "Pod",
        ["post-install"],
        "Succeeded",
    )
    pod_uid = kubectl("-n", TARGET, "get", "pod/" + POD, "-o", "jsonpath={.metadata.uid}")
    post = partial(fixture.post_closure, root / "admission", server)
    request = {"request_id": "flux-proof", "request_sha256": request_sha}
    owner = post("observe", request)
    assert owner["installation_sha256"] == digest(policy)
    command = request | {"epoch": owner["epoch"], "reason": "completed"}
    before = post("close", command)
    [effect] = before["effects"]
    assert before["state"] == "sealed" and not before["release_authorized"]
    assert effect["object_uid"] == pod_uid and effect["state"] == "settled"
    assert effect["event_sha256"] and effect["audit_id"]
    assert effect["terminal_status_sha256"] is None and "terminal_status" in effect["obligations"]

    observed = run(
        "docker",
        "run",
        "--rm",
        "--network=host",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "-v",
        f"{root / 'observer.kubeconfig'}:/observer:ro",
        "-v",
        f"{root / 'policy.json'}:/policy:ro",
        "-v",
        f"{root / 'state'}:/state",
        image,
        "birbverify.deployment_ownership_observe",
        "--kubeconfig",
        "/observer",
        "--policy",
        "/policy",
        "--journal",
        "/state/journal.sqlite",
        "--epoch",
        owner["epoch"],
        "--slot",
        POD,
    )
    after = post("close", command)
    [effect] = after["effects"]
    assert after["state"] == "sealed" and not after["release_authorized"]
    assert (
        effect["terminal_status_sha256"] == observed
        and "terminal_status" not in effect["obligations"]
    )
    assert "object_cleanup" in effect["obligations"]
    uri = (root / "state/journal.sqlite").as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as db:
        (record,) = db.execute(
            "SELECT observation FROM terminal_status WHERE slot=?", (POD,)
        ).fetchone()
    observation = json.loads(record)
    assert digest(observation) == observed and observation["uid"] == pod_uid
    assert observation["node_uid"] == policy["terminal_observer"]["node_uid"]
    assert observation["phase"] == "Succeeded"
    prepare, finish = observation["initContainers"]["prepare"], observation["containers"]["finish"]
    assert (
        prepare["exit_code"] == finish["exit_code"] == 0
        and prepare["container_id"] != finish["container_id"]
    )
    write(
        root / "receipt.json",
        dict(
            source_revision=run("git", "-C", fixture.REPO, "rev-parse", "HEAD"),
            source_dirty=bool(run("git", "-C", fixture.REPO, "status", "--porcelain")),
            verifier_image=image,
            guard=guard,
            kind_image=fixture.NODE,
            helm_hook=dict(
                release=POD,
                namespace=CONTROL,
                phase=hook["last_run"]["phase"],
                events=hook["events"],
            ),
            cluster_uid=policy["cluster_uid"],
            namespace_uid=policy["namespace_uid"],
            installation_sha256=digest(policy),
            scope=(
                "One Helm hook Pod CREATE. Helm storage, scheduling, status writes and cleanup "
                "are outside this fixture."
            ),
            before=before,
            terminal=observation,
            after=after,
        ),
    )
