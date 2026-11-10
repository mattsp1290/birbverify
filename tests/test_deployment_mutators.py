from copy import deepcopy

import pytest

from birbverify.deployment_mutators import (
    MutatorRejected,
    WriteScope,
    snapshot_mutators,
    verify_mutators,
)


@pytest.fixture
def namespace():
    return {"metadata": {"name": "owned", "uid": "namespace-uid", "labels": {"team": "owned"}}}


@pytest.fixture
def configuration():
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "MutatingWebhookConfiguration",
        "metadata": {"name": "mutator", "uid": "mutator-uid"},
        "webhooks": [
            {
                "name": "mutator.example.com",
                "clientConfig": {"url": "https://example.com"},
                "namespaceSelector": {"matchLabels": {"team": "outsider"}},
                "rules": [
                    {
                        "operations": ["*"],
                        "apiGroups": ["*"],
                        "apiVersions": ["*"],
                        "resources": ["*/*"],
                    }
                ],
            }
        ],
    }


def snapshot(configuration, namespace, **kwargs):
    return snapshot_mutators(
        [configuration], namespace, (WriteScope("", "v1", "pods", "CREATE"),), **kwargs
    )


def test_nonmatching_inventory_can_be_rechecked(configuration, namespace):
    pinned = snapshot(configuration, namespace)
    verify_mutators(pinned, [deepcopy(configuration)], deepcopy(namespace))


@pytest.mark.parametrize("change", ["labels", "uid", "name"])
def test_namespace_identity_is_frozen(configuration, namespace, change):
    pinned = snapshot(configuration, namespace)
    namespace["metadata"][change] = {"team": "other"} if change == "labels" else "other"
    with pytest.raises(MutatorRejected, match="drift"):
        verify_mutators(pinned, [configuration], namespace)


@pytest.mark.parametrize("change", ["add", "remove", "recreate", "client", "selector"])
def test_inventory_changes_require_reconciliation(configuration, namespace, change):
    pinned = snapshot(configuration, namespace)
    configs = [configuration]
    if change == "add":
        other = deepcopy(configuration)
        other["metadata"] = {"name": "other", "uid": "other"}
        configs.append(other)
    elif change == "remove":
        configs = []
    elif change == "recreate":
        configuration["metadata"]["uid"] = "new-uid"
    elif change == "client":
        configuration["webhooks"][0]["clientConfig"]["url"] = "https://changed.com"
    else:
        configuration["webhooks"][0]["namespaceSelector"] = {}
    with pytest.raises(MutatorRejected):
        verify_mutators(pinned, configs, namespace)


@pytest.mark.parametrize(
    "selector, matches",
    [
        ({"matchLabels": {"missing": ""}}, False),
        ({"matchExpressions": [{"key": "missing", "operator": "NotIn", "values": ["x"]}]}, True),
        ({"matchExpressions": [{"key": "missing", "operator": "In", "values": ["x"]}]}, False),
        ({"matchExpressions": [{"key": "team", "operator": "Exists"}]}, True),
        ({"matchExpressions": [{"key": "team", "operator": "DoesNotExist"}]}, False),
    ],
)
def test_namespace_selector_semantics(configuration, namespace, selector, matches):
    configuration["webhooks"][0]["namespaceSelector"] = selector
    if matches:
        with pytest.raises(MutatorRejected, match="matching"):
            snapshot(configuration, namespace)
    else:
        snapshot(configuration, namespace)


@pytest.mark.parametrize(
    "pattern, subresource, matches",
    [
        ("*", "", True),
        ("*", "status", False),
        ("*/*", "", True),
        ("*/*", "status", True),
        ("pods/*", "", False),
        ("pods/*", "status", True),
        ("*/status", "status", True),
        ("pods/status", "status", True),
        ("pods/status", "log", False),
        ("deployments/*", "status", False),
    ],
)
def test_resource_wildcards(configuration, namespace, pattern, subresource, matches):
    webhook = configuration["webhooks"][0]
    webhook["namespaceSelector"] = {}
    webhook["rules"][0]["resources"] = [pattern]
    writes = (WriteScope("", "v1", "pods", "UPDATE", subresource),)
    if matches:
        with pytest.raises(MutatorRejected, match="matching"):
            snapshot_mutators([configuration], namespace, writes)
    else:
        snapshot_mutators([configuration], namespace, writes)


@pytest.mark.parametrize(
    "field, value",
    [
        ("objectSelector", {"matchLabels": {"excluded": "yes"}}),
        ("matchConditions", [{"name": "never", "expression": "false"}]),
    ],
)
def test_mutable_object_or_cel_exclusion_is_not_proof(configuration, namespace, field, value):
    webhook = configuration["webhooks"][0]
    webhook[field] = value
    snapshot(configuration, namespace)
    webhook["namespaceSelector"] = {}
    with pytest.raises(MutatorRejected, match="matching"):
        snapshot(configuration, namespace)


@pytest.mark.parametrize("field, value", [("apiVersions", ["v2"]), ("apiGroups", ["other"])])
def test_equivalent_does_not_assume_version_or_group_disjointness(
    configuration, namespace, field, value
):
    webhook = configuration["webhooks"][0]
    webhook["namespaceSelector"] = {}
    webhook["rules"][0][field] = value
    with pytest.raises(MutatorRejected, match="matching"):
        snapshot(configuration, namespace)
    webhook["matchPolicy"] = "Exact"
    snapshot(configuration, namespace)


def test_cleanup_is_in_scope(configuration, namespace):
    webhook = configuration["webhooks"][0]
    webhook["namespaceSelector"] = {}
    webhook["rules"][0]["operations"] = ["DELETE"]
    snapshot(configuration, namespace)
    with pytest.raises(MutatorRejected, match="matching"):
        snapshot_mutators(
            [configuration],
            namespace,
            (WriteScope("", "v1", "pods", "CREATE"), WriteScope("", "v1", "pods", "DELETE")),
        )


def test_namespace_selector_cannot_exclude_cluster_write(configuration, namespace):
    with pytest.raises(MutatorRejected, match="matching"):
        snapshot_mutators(
            [configuration], namespace, (WriteScope("", "v1", "nodes", "UPDATE", scope="Cluster"),)
        )


@pytest.mark.parametrize(
    "field, value",
    [
        ("matchPolicy", "Future"),
        ("reinvocationPolicy", "Future"),
        ("namespaceSelector", {"future": True}),
        ("namespaceSelector", {"matchExpressions": [{"key": "x", "operator": "Future"}]}),
        ("namespaceSelector", {"matchExpressions": [{"key": "x", "operator": "In"}]}),
        ("namespaceSelector", {"matchLabels": {"bad key": "x"}}),
        ("rules", [{"future": True}]),
    ],
)
def test_unknown_or_invalid_semantics_rejected(configuration, namespace, field, value):
    configuration["webhooks"][0][field] = value
    with pytest.raises(MutatorRejected):
        snapshot(configuration, namespace)


@pytest.mark.parametrize("field", ["policies", "bindings"])
def test_admission_policies_unsupported(configuration, namespace, field):
    with pytest.raises(MutatorRejected, match="unsupported"):
        snapshot(configuration, namespace, **{field: [{"metadata": {"name": "policy"}}]})
