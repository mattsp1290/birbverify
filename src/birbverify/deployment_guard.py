"""Inspect and render the Kubernetes 1.33 installation guard."""

import argparse
import json
from pathlib import Path

from birbverify.contract import digest
from birbverify.deployment_mutators import _namespace, _selector_matches
from birbverify.kubernetes_api import ApiError, KubernetesAPI

GROUP = "admissionregistration.k8s.io"
VERSION = GROUP + "/v1"
BASE = "/apis/" + VERSION
NAME_LABEL = "kubernetes.io/metadata.name"


def _webhook_pin(config):
    meta = config["metadata"]
    if not meta.get("uid") or meta.get("deletionTimestamp"):
        raise ValueError("webhook configuration is missing a stable UID")
    return {"name": meta["name"], "uid": meta["uid"], "webhooks_sha256": digest(config["webhooks"])}


def inventory(api, namespace, webhook):
    if api.request("GET", "/version")["gitVersion"] != "v1.33.1":
        raise ValueError("guard requires the reviewed Kubernetes v1.33.1")
    for version in api.request("GET", "/apis/" + GROUP)["versions"]:
        resources = api.request("GET", "/apis/" + version["groupVersion"])["resources"]
        if any(r["name"].startswith("mutatingadmissionpolic") for r in resources):
            raise ValueError("served MutatingAdmissionPolicy API is unsupported")
    system = api.request("GET", "/api/v1/namespaces/kube-system")
    target = api.request("GET", "/api/v1/namespaces/" + namespace)
    ns = _namespace(target)
    labels = dict(ns.labels)
    if (
        ns.name != namespace
        or labels.get(NAME_LABEL) != namespace
        or target["metadata"].get("deletionTimestamp")
        or target["status"]["phase"] != "Active"
    ):
        raise ValueError("expected active target namespace")
    configs = api.request("GET", BASE + "/mutatingwebhookconfigurations")
    if configs["metadata"].get("continue"):
        raise ValueError("incomplete mutator inventory")
    pins = []
    for config in configs["items"]:
        for hook in config["webhooks"]:
            if _selector_matches(hook.get("namespaceSelector", {}), labels) or any(
                rule.get("scope") != "Namespaced" for rule in hook.get("rules", [])
            ):
                raise ValueError("mutator must exclude the target and all cluster-scoped requests")
        pins.append(_webhook_pin(config))
    validator = api.request("GET", BASE + "/validatingwebhookconfigurations/" + webhook)
    return {
        "schema_version": "birbverify.deployment.guard.v1",
        "cluster_uid": system["metadata"]["uid"],
        "namespace": namespace,
        "namespace_uid": ns.uid,
        "labels_sha256": digest(labels),
        "mutators": sorted(pins, key=lambda p: p["name"]),
        "validator": _webhook_pin(validator),
    }


def manifests(pins):
    namespace = pins["namespace"]
    names = json.dumps([p["name"] for p in pins["mutators"]])
    key = json.dumps(NAME_LABEL)
    excluded = (
        "object.webhooks.all(h, has(h.namespaceSelector) && "
        "has(h.namespaceSelector.matchExpressions) && "
        "h.namespaceSelector.matchExpressions.exists(e, "
        f"e.key == {key} && e.operator == 'NotIn' && {json.dumps(namespace)} in e.values) && "
        "(!has(h.rules) || h.rules.all(r, has(r.scope) && r.scope == 'Namespaced')))"
    )
    resources = [
        ("namespace", "", ["namespaces", "namespaces/*"], [namespace], "false"),
        (
            "validator",
            GROUP,
            ["validatingwebhookconfigurations"],
            [pins["validator"]["name"]],
            "false",
        ),
        (
            "mutators",
            GROUP,
            ["mutatingwebhookconfigurations"],
            [],
            f"!(request.name in {names}) && (request.operation == 'DELETE' || {excluded})",
        ),
    ]
    result = []
    for label, group, kinds, frozen_names, validation in resources:
        name = f"bv-{namespace}-{label}"
        rule = dict(
            apiGroups=[group],
            apiVersions=["v1"],
            resources=kinds,
            scope="Cluster",
            operations=["CREATE", "UPDATE", "DELETE"],
        )
        if frozen_names:
            rule["resourceNames"] = frozen_names
        result.append(
            {
                "apiVersion": VERSION,
                "kind": "ValidatingAdmissionPolicy",
                "metadata": {"name": name},
                "spec": {
                    "failurePolicy": "Fail",
                    "matchConstraints": {
                        "matchPolicy": "Equivalent",
                        "namespaceSelector": {},
                        "objectSelector": {},
                        "resourceRules": [rule],
                    },
                    "validations": [
                        {"expression": validation, "message": f"{name} guard denied write"}
                    ],
                },
            }
        )
        result.append(
            {
                "apiVersion": VERSION,
                "kind": "ValidatingAdmissionPolicyBinding",
                "metadata": {"name": name},
                "spec": {"policyName": name, "validationActions": ["Deny"]},
            }
        )
    return result


def _probe(api, method, path, obj, guard):
    try:
        api.request(method, path + "?dryRun=All", obj)
    except ApiError as error:
        if guard + " guard denied write" in str(error):
            return
        raise ValueError("guard probe failed without an attributable denial: " + guard) from error
    raise ValueError("guard probe was allowed: " + guard)


def verify_initial_installation(api, pins):
    proof = {}
    for doc in manifests(pins):
        resource = (
            "validatingadmissionpolicies"
            if doc["kind"] == "ValidatingAdmissionPolicy"
            else "validatingadmissionpolicybindings"
        )
        name = doc["metadata"]["name"]
        live = api.request("GET", f"{BASE}/{resource}/{name}")
        meta = live["metadata"]
        if live["spec"] != doc["spec"] or meta.get("deletionTimestamp") or not meta.get("uid"):
            raise ValueError("guard content mismatch: " + name)
        if doc["kind"] == "ValidatingAdmissionPolicy":
            status = live.get("status", {})
            if meta["generation"] != status.get("observedGeneration") or status.get(
                "typeChecking", {}
            ).get("expressionWarnings"):
                raise ValueError("guard type check pending or failed: " + name)
        proof[resource + "/" + name] = {"uid": meta["uid"], "spec_sha256": digest(live["spec"])}
    if inventory(api, pins["namespace"], pins["validator"]["name"]) != pins:
        raise ValueError("bootstrap inventory changed")
    namespace = pins["namespace"]
    prefix = f"bv-{namespace}-"
    namespace_path = "/api/v1/namespaces/" + namespace
    validator_path = BASE + "/validatingwebhookconfigurations/" + pins["validator"]["name"]
    for path, guard in [(namespace_path, "namespace"), (validator_path, "validator")]:
        _probe(api, "PUT", path, api.request("GET", path), prefix + guard)
    _probe(
        api,
        "POST",
        BASE + "/mutatingwebhookconfigurations",
        {
            "apiVersion": VERSION,
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"generateName": "birbverify-probe-"},
            "webhooks": [
                {
                    "name": "guard.birbverify.test",
                    "failurePolicy": "Fail",
                    "clientConfig": {"service": {"namespace": namespace, "name": "unused"}},
                    "sideEffects": "None",
                    "admissionReviewVersions": ["v1"],
                    "rules": [],
                }
            ],
        },
        prefix + "mutators",
    )
    return {"inventory_sha256": digest(pins), "admission": proof}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inspect", "render", "verify-install"))
    parser.add_argument("--kubeconfig", required=True, type=Path)
    parser.add_argument("--context", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--validator", required=True)
    parser.add_argument("--expected-sha256")
    args = parser.parse_args()
    api = KubernetesAPI(args.kubeconfig, args.context)
    pins = inventory(api, args.namespace, args.validator)
    output = {"inventory": pins, "inventory_sha256": digest(pins)}
    if args.action != "inspect":
        if digest(pins) != args.expected_sha256:
            raise ValueError("reviewed installation inventory required")
        if args.action == "render":
            output = {"apiVersion": "v1", "kind": "List", "items": manifests(pins)}
        else:
            output = verify_initial_installation(api, pins)
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
