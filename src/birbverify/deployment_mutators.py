"""Conservative installation pins, not an admission enforcement mechanism."""

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any


class MutatorRejected(ValueError):
    pass


@dataclass(frozen=True, order=True)
class WriteScope:
    group: str
    version: str
    resource: str
    operation: str
    subresource: str = ""
    scope: str = "Namespaced"


@dataclass(frozen=True)
class NamespacePin:
    name: str
    uid: str
    labels: tuple[tuple[str, str], ...]


@dataclass(frozen=True, order=True)
class MutatorPin:
    name: str
    uid: str
    webhooks_digest: str


@dataclass(frozen=True)
class MutatorSnapshot:
    namespace: NamespacePin
    configurations: tuple[MutatorPin, ...]
    writes: tuple[WriteScope, ...]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MutatorRejected(message)


def _namespace(namespace: dict[str, Any]) -> NamespacePin:
    _require(isinstance(namespace, dict), "invalid namespace")
    metadata = namespace.get("metadata", {})
    _require(isinstance(metadata, dict), "invalid namespace metadata")
    name, uid = metadata.get("name"), metadata.get("uid")
    labels = metadata.get("labels", {})
    _require(isinstance(name, str) and bool(name), "namespace name required")
    _require(isinstance(uid, str) and bool(uid), "namespace UID required")
    _require(isinstance(labels, dict), "invalid namespace labels")
    _require(
        all(_label_key(k) and _label_value(v) for k, v in labels.items()),
        "invalid namespace labels",
    )
    return NamespacePin(name, uid, tuple(sorted(labels.items())))


def _label_key(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parts = value.split("/")
    name = parts[-1]
    valid_name = len(name) <= 63 and re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?", name
    )
    if len(parts) == 1:
        return bool(valid_name)
    return bool(
        len(parts) == 2
        and valid_name
        and len(parts[0]) <= 253
        and all(
            len(part) <= 63 and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", part)
            for part in parts[0].split(".")
        )
    )


def _label_value(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= 63
        and (not value or bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?", value)))
    )


def _selector_matches(selector: Any, labels: dict[str, str]) -> bool:
    _require(isinstance(selector, dict), "invalid namespace selector")
    _require(
        not set(selector) - {"matchLabels", "matchExpressions"}, "unknown namespace selector field"
    )
    match_labels = selector.get("matchLabels", {})
    expressions = selector.get("matchExpressions", [])
    _require(
        isinstance(match_labels, dict) and isinstance(expressions, list),
        "invalid namespace selector",
    )
    results = []
    for key, value in match_labels.items():
        _require(_label_key(key) and _label_value(value), "invalid selector label")
        results.append(key in labels and labels[key] == value)
    for expression in expressions:
        _require(isinstance(expression, dict), "invalid selector expression")
        _require(
            not set(expression) - {"key", "operator", "values"}, "unknown selector expression field"
        )
        key, operator = expression.get("key"), expression.get("operator")
        values = expression.get("values", [])
        _require(_label_key(key), "invalid selector key")
        _require(
            isinstance(values, list) and all(_label_value(v) for v in values),
            "invalid selector values",
        )
        _require(operator in {"In", "NotIn", "Exists", "DoesNotExist"}, "unknown selector operator")
        _require(
            bool(values) if operator in {"In", "NotIn"} else not values,
            "invalid selector values for operator",
        )
        if operator == "In":
            results.append(key in labels and labels[key] in values)
        elif operator == "NotIn":
            results.append(key not in labels or labels[key] not in values)
        elif operator == "Exists":
            results.append(key in labels)
        else:
            results.append(key not in labels)
    return all(results)


def _strings(rule: dict[str, Any], field: str) -> list[str]:
    values = rule.get(field)
    _require(isinstance(values, list) and bool(values), f"invalid rule {field}")
    _require(all(isinstance(v, str) for v in values), f"invalid rule {field}")
    return values


def _resource_matches(pattern: str, write: WriteScope) -> bool:
    if pattern == "*/*":
        return True
    parts = pattern.split("/")
    if len(parts) == 1:
        return not write.subresource and parts[0] in {"*", write.resource}
    return (
        bool(write.subresource)
        and parts[0] in {"*", write.resource}
        and parts[1] in {"*", write.subresource}
    )


def _rule_matches(rule: Any, write: WriteScope, policy: str) -> bool:
    _require(isinstance(rule, dict), "invalid webhook rule")
    _require(
        not set(rule) - {"operations", "apiGroups", "apiVersions", "resources", "scope"},
        "unknown webhook rule field",
    )
    operations = _strings(rule, "operations")
    groups = _strings(rule, "apiGroups")
    versions = _strings(rule, "apiVersions")
    resources = _strings(rule, "resources")
    scope = rule.get("scope", "*")
    _require(
        set(operations) <= {"*", "CREATE", "UPDATE", "DELETE", "CONNECT"},
        "unknown webhook operation",
    )
    _require(scope in {"*", "Namespaced", "Cluster"}, "unknown webhook scope")
    _require(all(re.fullmatch(r"\*|[a-z0-9][a-z0-9.\-]*|", g) for g in groups), "invalid API group")
    _require(all(re.fullmatch(r"\*|[a-z0-9]+", v) for v in versions), "invalid API version")
    _require(
        all(re.fullmatch(r"(?:\*|[a-z0-9]+)(?:/(?:\*|[a-z0-9]+))?", r) for r in resources),
        "invalid resource pattern",
    )
    return (
        ("*" in operations or write.operation in operations)
        and (policy == "Equivalent" or "*" in groups or write.group in groups)
        and (policy == "Equivalent" or "*" in versions or write.version in versions)
        and (scope == "*" or scope == write.scope)
        and any(_resource_matches(pattern, write) for pattern in resources)
    )


def snapshot_mutators(
    configurations: list[dict[str, Any]],
    namespace: dict[str, Any],
    writes: tuple[WriteScope, ...],
    *,
    policies: tuple = (),
    bindings: tuple = (),
) -> MutatorSnapshot:
    """Pin a complete API inventory covering execution and cleanup writes.

    The caller must supply complete discovery/list results and enforce frozen
    namespace identity and labels. This read alone cannot close admission races.
    """
    _require(
        isinstance(policies, (tuple, list)) and not policies, "MutatingAdmissionPolicy unsupported"
    )
    _require(
        isinstance(bindings, (tuple, list)) and not bindings,
        "MutatingAdmissionPolicyBinding unsupported",
    )
    ns = _namespace(namespace)
    _require(isinstance(writes, (tuple, list)) and bool(writes), "write scope required")
    for write in writes:
        _require(isinstance(write, WriteScope), "invalid write scope")
        _require(
            write.operation in {"CREATE", "UPDATE", "DELETE", "CONNECT"}, "invalid write operation"
        )
        _require(write.scope in {"Namespaced", "Cluster"}, "invalid write scope")
        _require(
            isinstance(write.group, str)
            and bool(re.fullmatch(r"[a-z0-9][a-z0-9.\-]*|", write.group))
            and isinstance(write.version, str)
            and bool(re.fullmatch(r"[a-z0-9]+", write.version))
            and isinstance(write.resource, str)
            and bool(re.fullmatch(r"[a-z0-9]+", write.resource))
            and isinstance(write.subresource, str)
            and bool(re.fullmatch(r"[a-z0-9]*", write.subresource)),
            "invalid write resource",
        )
    _require(isinstance(configurations, list), "complete configuration list required")
    pins = []
    for config in configurations:
        _require(isinstance(config, dict), "invalid mutating configuration")
        _require(
            config.get("apiVersion") == "admissionregistration.k8s.io/v1"
            and config.get("kind") == "MutatingWebhookConfiguration",
            "unknown mutating configuration kind",
        )
        metadata = config.get("metadata", {})
        _require(isinstance(metadata, dict), "invalid mutator metadata")
        name, uid = metadata.get("name"), metadata.get("uid")
        _require(
            isinstance(name, str) and bool(name) and isinstance(uid, str) and bool(uid),
            "mutator name and UID required",
        )
        webhooks = config.get("webhooks")
        _require(isinstance(webhooks, list), "invalid webhooks")
        for webhook in webhooks:
            _require(isinstance(webhook, dict), "invalid webhook")
            _require(
                not set(webhook)
                - {
                    "name",
                    "clientConfig",
                    "rules",
                    "failurePolicy",
                    "matchPolicy",
                    "namespaceSelector",
                    "objectSelector",
                    "sideEffects",
                    "timeoutSeconds",
                    "admissionReviewVersions",
                    "reinvocationPolicy",
                    "matchConditions",
                },
                "unknown webhook field",
            )
            policy = webhook.get("matchPolicy", "Equivalent")
            _require(policy in {"Exact", "Equivalent"}, "unknown match policy")
            _require(
                webhook.get("reinvocationPolicy", "Never") in {"Never", "IfNeeded"},
                "unknown reinvocation policy",
            )
            namespace_matches = _selector_matches(
                webhook.get("namespaceSelector", {}), dict(ns.labels)
            )
            rules = webhook.get("rules", [])
            _require(isinstance(rules, list), "invalid webhook rules")
            for rule in rules:
                for write in writes:
                    matches = _rule_matches(rule, write, policy)
                    _require(
                        not (matches and (write.scope == "Cluster" or namespace_matches)),
                        f"potentially matching mutator {name}",
                    )
        try:
            encoded = json.dumps(
                webhooks, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
        except (ValueError, TypeError) as error:
            raise MutatorRejected("noncanonical webhook content") from error
        pins.append(MutatorPin(name, uid, sha256(encoded).hexdigest()))
    _require(len({pin.name for pin in pins}) == len(pins), "duplicate mutator name")
    _require(len({pin.uid for pin in pins}) == len(pins), "duplicate mutator UID")
    return MutatorSnapshot(ns, tuple(sorted(pins)), tuple(sorted(set(writes))))


def verify_mutators(
    snapshot: MutatorSnapshot,
    configurations: list[dict[str, Any]],
    namespace: dict[str, Any],
    *,
    policies: tuple = (),
    bindings: tuple = (),
) -> None:
    current = snapshot_mutators(
        configurations, namespace, snapshot.writes, policies=policies, bindings=bindings
    )
    _require(current == snapshot, "mutating admission installation drift")
