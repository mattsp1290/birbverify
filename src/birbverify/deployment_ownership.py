"""Installation-pinned CREATE ownership for one deployment epoch."""

import re
from typing import Literal

from pydantic import Field, TypeAdapter, model_validator

from birbverify.contract import Id, Record, RequestId, Sha, digest
from birbverify.deployment_activity import account_activity_state
from birbverify.deployment_journal import Journal, _encode, _identifier
from birbverify.kubernetes_contract import Name

# These are the exact versions for which the journal compares admission and audit objects.
_RESOURCES = {
    "ConfigMap": ("", "v1", "configmaps"),
    "Deployment": ("apps", "v1", "deployments"),
    "StatefulSet": ("apps", "v1", "statefulsets"),
    "ReplicaSet": ("apps", "v1", "replicasets"),
    "ControllerRevision": ("apps", "v1", "controllerrevisions"),
    "Pod": ("", "v1", "pods"),
    "Service": ("", "v1", "services"),
    "EndpointSlice": ("discovery.k8s.io", "v1", "endpointslices"),
    "Endpoints": ("", "v1", "endpoints"),
    "CronJob": ("batch", "v1", "cronjobs"),
    "NetworkPolicy": ("networking.k8s.io", "v1", "networkpolicies"),
    "ServiceAccount": ("", "v1", "serviceaccounts"),
    "PersistentVolumeClaim": ("", "v1", "persistentvolumeclaims"),
}
_PARENTS = {
    "ReplicaSet": {"Deployment"},
    "Pod": {"ReplicaSet", "StatefulSet"},
    "ControllerRevision": {"StatefulSet"},
    "EndpointSlice": {"Service"},
    "PersistentVolumeClaim": {"StatefulSet"},
}
_OBJECT_NAME = TypeAdapter(Name)
_IMAGE = re.compile(r"[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}")


class CreateSlot(Record):
    slot: Id
    kind: str
    name: Name | None = None
    generate_name: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9.-]{0,57}-$")
    parent_slot: Id | None = None
    principal_sha256: Sha
    object_sha256: Sha

    @model_validator(mode="after")
    def supported(self):
        if self.kind not in _RESOURCES or (self.name is None) == (self.generate_name is None):
            raise ValueError("expected a supported kind and one name or generated prefix")
        if self.generate_name and not self.parent_slot:
            raise ValueError("only an owned child may use a generated name")
        if (
            self.kind in {"ReplicaSet", "ControllerRevision", "EndpointSlice"}
            and not self.parent_slot
        ):
            raise ValueError("generated controller objects require an owned parent")
        return self


class TerminalObserverPin(Record):
    node_name: Name
    node_uid: Id
    context: Id
    kubeconfig_sha256: Sha


class OwnershipPolicy(Record):
    schema_version: Literal["birbverify.deployment.ownership.v1"]
    cluster_uid: Id
    namespace: Name
    namespace_uid: Id
    webhook_name: Name
    admission_client_sha256: Sha
    closure_client_sha256: Sha
    audit_client_sha256: Sha
    terminal_observer: TerminalObserverPin | None = None
    rules: tuple[CreateSlot, ...] = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def bindings(self):
        pins = (self.admission_client_sha256, self.closure_client_sha256, self.audit_client_sha256)
        if len(set(pins)) != len(pins):
            raise ValueError("each caller needs a distinct certificate")
        by_id = {rule.slot: rule.kind for rule in self.rules}
        if len(by_id) != len(self.rules):
            raise ValueError("duplicate ownership slot")
        for rule in self.rules:
            if rule.parent_slot and by_id.get(rule.parent_slot) not in _PARENTS.get(rule.kind, {}):
                raise ValueError("unsupported controller edge")
        return self


class InstalledRequest(Record):
    request_id: RequestId
    request_sha256: Sha


class Owner(InstalledRequest):
    schema_version: Literal["birbverify.deployment.owner.v1"] = "birbverify.deployment.owner.v1"
    installation_sha256: Sha
    epoch: Id
    state: Literal["active", "sealed", "quarantined"]


class CloseCommand(InstalledRequest):
    epoch: Id
    reason: Literal["completed", "cancelled", "worker_lost"]


class OwnedEffect(Record):
    slot: Id
    state: Literal["pending", "settled", "quarantined"]
    object_uid: Id | None
    audit_id: Id | None
    event_sha256: Sha | None
    obligations: tuple[str, ...]
    terminal_status_sha256: Sha | None


class ClosureProgress(CloseCommand):
    schema_version: Literal["birbverify.deployment.closure.progress.v1"] = (
        "birbverify.deployment.closure.progress.v1"
    )
    installation_sha256: Sha
    cluster_uid: Id
    namespace_uid: Id
    state: Literal["sealed", "quarantined"]
    effects: tuple[OwnedEffect, ...] = Field(max_length=512)
    account_activity_state: Literal["absent", "running", "passed", "failed", "unknown"]
    installation_obligations: tuple[str, ...]
    release_authorized: Literal[False] = False


_OBLIGATIONS = {
    "Pod": ("terminal_status",),
    "Service": ("route_cleanup",),
    "Endpoints": ("route_cleanup",),
    "EndpointSlice": ("route_cleanup",),
    "Deployment": ("stop_reconciliation",),
    "ReplicaSet": ("stop_reconciliation",),
    "StatefulSet": ("stop_reconciliation", "restore_storage"),
    "CronJob": ("stop_reconciliation",),
    "PersistentVolumeClaim": ("restore_storage",),
}


def _owned_effect(slot, state, uid, kind, terminal_digest, audit_id, event_sha):
    if state == "settled":
        obligations = ("object_cleanup",) + _OBLIGATIONS.get(kind, ())
        if terminal_digest:
            obligations = tuple(item for item in obligations if item != "terminal_status")
    else:
        obligations = ("api_completion",)
    return OwnedEffect(
        slot=slot,
        state=state,
        object_uid=uid,
        obligations=obligations,
        terminal_status_sha256=terminal_digest,
        audit_id=audit_id if state == "settled" else None,
        event_sha256=event_sha if state == "settled" else None,
    )


def object_shape_sha256(obj: dict, *, generated: bool, owned: bool) -> str:
    """Keep all object fields except server-assigned identities checked separately."""
    metadata = obj["metadata"].copy()
    for key in ("uid", "resourceVersion", "generation", "creationTimestamp", "managedFields"):
        metadata.pop(key, None)
    if generated:
        metadata.pop("name")
    if owned:
        refs = metadata["ownerReferences"]
        if len(refs) != 1 or refs[0].get("controller") is not True:
            raise ValueError("expected one controlling owner")
        ref = refs[0].copy()
        del ref["uid"], ref["name"]
        metadata["ownerReferences"] = [ref]
    elif metadata.get("ownerReferences"):
        raise ValueError("unexpected owner")
    return digest(obj | {"metadata": metadata})


def _check_execution(obj):
    spec = obj.get("spec", {})
    kind = obj["kind"]
    if kind == "CronJob":
        if spec.get("suspend") is not True:
            raise ValueError("seed CronJob must stay suspended")
        spec = spec["jobTemplate"]["spec"]["template"]["spec"]
    elif kind in {"Deployment", "StatefulSet", "ReplicaSet"}:
        spec = spec["template"]["spec"]
    elif kind != "Pod":
        return
    if not spec.get("containers") or spec.get("ephemeralContainers"):
        raise ValueError("unsupported executable Pod")
    for container in [*spec["containers"], *spec.get("initContainers", [])]:
        if not _IMAGE.fullmatch(container["image"]):
            raise ValueError("every regular and init image requires a digest")


class OwnershipJournal(Journal):
    def __init__(self, path, policy: OwnershipPolicy, *, expected_epoch=None):
        self.policy = policy
        self.installation_sha256 = digest(policy.model_dump(mode="json", exclude_none=True))
        super().__init__(
            path,
            self.installation_sha256,
            policy.webhook_name,
            policy.namespace,
            expected_epoch=expected_epoch,
        )
        self.require_audit_source(policy.cluster_uid, policy.audit_client_sha256)

    def _validate_admission(self, request):
        if (
            not isinstance(request, dict)
            or not _identifier(request.get("uid"))
            or request.get("operation") != "CREATE"
            or request.get("oldObject") is not None
            or request.get("dryRun") is not False
            or request.get("namespace") != self.namespace
            or request.get("subResource")
            or request.get("requestSubResource")
        ):
            raise ValueError("outside supported CREATE scope")
        obj = request.get("object")
        if not isinstance(obj, dict) or obj.get("kind") not in _RESOURCES:
            raise ValueError("unsupported object kind")
        group, version, resource = _RESOURCES[obj["kind"]]
        expected_resource = {"group": group, "version": version, "resource": resource}
        expected_kind = {"group": group, "version": version, "kind": obj["kind"]}
        for key, expected in (("resource", expected_resource), ("kind", expected_kind)):
            original = "request" + key.title()
            if any(
                {"group": ""} | request.get(field, {}) != expected
                for field in (key, original)
                if field == key or field in request
            ):
                raise ValueError("resource or conversion mismatch")
        metadata = obj.get("metadata", {})
        user = request.get("userInfo", {})
        if (
            not user.get("username")
            or metadata.get("namespace") != self.namespace
            or not isinstance(request.get("name"), str)
            or metadata.get("name") != request["name"]
            or obj.get("apiVersion") != (f"{group}/{version}" if group else version)
        ):
            raise ValueError("admission identity mismatch")
        _OBJECT_NAME.validate_python(request["name"])
        try:
            _check_execution(obj)
        except (KeyError, TypeError, AttributeError) as error:
            raise ValueError("invalid workload") from error

    def _reserve_intent(self, db, request):
        obj = request["object"]
        metadata = obj["metadata"]
        principal = digest(request["userInfo"])
        candidates = [
            rule
            for rule in self.policy.rules
            if rule.kind == obj["kind"]
            and rule.principal_sha256 == principal
            and (
                rule.name == metadata["name"]
                if rule.name
                else (
                    metadata.get("generateName") == rule.generate_name
                    and metadata["name"].startswith(rule.generate_name)
                    and len(metadata["name"]) > len(rule.generate_name)
                )
            )
        ]
        matches = []
        for slot in candidates:
            try:
                shape = object_shape_sha256(
                    obj, generated=bool(slot.generate_name), owned=bool(slot.parent_slot)
                )
            except (KeyError, TypeError, ValueError, AttributeError):
                continue
            if shape == slot.object_sha256 and self._matches_parent(db, slot, metadata):
                matches.append(slot)
        if len(matches) != 1:
            raise ValueError("no unique approved CREATE slot")
        rule = matches[0]
        if db.execute("SELECT 1 FROM ownership_slots WHERE slot=?", (rule.slot,)).fetchone():
            raise ValueError("CREATE slot already reserved")
        db.execute("INSERT INTO ownership_slots VALUES (?, ?)", (rule.slot, request["uid"]))

    def _matches_parent(self, db, slot, metadata):
        if not slot.parent_slot:
            return True
        ref = metadata["ownerReferences"][0]
        parent = db.execute(
            "SELECT json_extract(data,'$.request.object.apiVersion'),"
            "json_extract(data,'$.request.object.kind'), json_extract(data,'$.request.name'),"
            "json_extract(data,'$.evidence.object_uid') FROM ownership_slots "
            "JOIN intents ON uid=review_uid WHERE slot=? "
            "AND json_extract(data,'$.state')='settled'",
            (slot.parent_slot,),
        ).fetchone()
        return parent == tuple(ref[key] for key in ("apiVersion", "kind", "name", "uid"))

    def observe_owner(self, request: InstalledRequest):
        with self._transaction() as db:
            row = self._epoch(db)
            if (row["request_id"], row["request_sha256"]) != (
                request.request_id,
                request.request_sha256,
            ):
                raise ValueError("request identity mismatch")
            return Owner(
                request_id=row["request_id"],
                request_sha256=row["request_sha256"],
                installation_sha256=self.installation_sha256,
                epoch=row["epoch"],
                state=row["state"],
            ).model_dump(mode="json")

    def close_owned(self, command: CloseCommand):
        with self._transaction() as db:
            row = self._epoch(db, command.epoch)
            if (row["request_id"], row["request_sha256"]) != (
                command.request_id,
                command.request_sha256,
            ):
                raise ValueError("closure identity mismatch")
            if row["state"] == "active":
                row["state"] = "sealed"
            row.setdefault("close_reason", command.reason)
            db.execute("UPDATE epoch SET data=?", (_encode(row),))
        # Commit the seal even if a damaged evidence row subsequently prevents reporting.
        with self._transaction() as db:
            row = self._epoch(db, command.epoch)
            effects = db.execute(
                "SELECT slot,json_extract(data,'$.state'),"
                "json_extract(data,'$.evidence.object_uid'),"
                "json_extract(data,'$.request.object.kind'),"
                "terminal_status.digest, json_extract(data,'$.evidence.audit_id'), "
                "json_extract(data,'$.event_sha256') FROM ownership_slots "
                "JOIN intents ON uid=review_uid "
                "LEFT JOIN terminal_status USING(slot) ORDER BY slot"
            ).fetchall()
            return ClosureProgress(
                installation_sha256=self.installation_sha256,
                cluster_uid=self.policy.cluster_uid,
                namespace_uid=self.policy.namespace_uid,
                epoch=row["epoch"],
                request_id=row["request_id"],
                request_sha256=row["request_sha256"],
                reason=row["close_reason"],
                state=row["state"],
                effects=tuple(_owned_effect(*effect) for effect in effects),
                installation_obligations=(
                    "writer_and_admission_integrity",
                    "reconciliation_quiescence",
                    "baseline_restoration",
                ),
                account_activity_state=account_activity_state(db, row["epoch"]),
            ).model_dump(mode="json")
