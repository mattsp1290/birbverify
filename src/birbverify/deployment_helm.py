"""Admission and audit projection for the first Helm 3 install of a named release."""

import base64
import json
import re
import zlib
from datetime import datetime
from typing import Annotated

from pydantic import Field

from birbverify.contract import Commit, Record, Sha, digest
from birbverify.deployment_http import strict_json

_RELEASE_NAME = r"^[a-z0-9](?:[a-z0-9.-]{0,51}[a-z0-9])?$"
_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}")
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)")
_DYNAMIC_INFO = {"first_deployed", "last_deployed", "description", "status"}
_MAX_RELEASE = 4 * 1024 * 1024
_RESOURCE = {"group": "", "version": "v1", "resource": "secrets"}
_KIND = {"group": "", "version": "v1", "kind": "Secret"}


class HelmReleasePin(Record):
    release_name: Annotated[str, Field(pattern=_RELEASE_NAME)]
    source_revision: Commit
    principal_sha256: Sha
    content_sha256: Sha
    failed_description_sha256: Sha | None = None

    def slot(self, phase):
        return "helm-" + self.release_name + "-" + phase


def release_content_sha256(release):
    """Hash a reviewed Helm dry-run JSON release, including all hooks, notes and values."""
    content = release | {
        "info": {k: v for k, v in release["info"].items() if k not in _DYNAMIC_INFO}
    }
    return digest(
        json.dumps(content, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    )


def _release(data):
    if not isinstance(data, str) or not 0 < len(data) <= 1400000:
        raise ValueError("invalid encoded Helm release length")
    compressed = base64.b64decode(base64.b64decode(data, validate=True), validate=True)
    if compressed[:10] != bytes.fromhex("1f8b08000000000002ff"):
        raise ValueError("unsupported Helm gzip header")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    result = decoder.decompress(compressed, _MAX_RELEASE + 1)
    if len(result) > _MAX_RELEASE or not decoder.eof or decoder.unused_data:
        raise ValueError("invalid compressed Helm release")
    release = strict_json(result)
    pending = [(release, 1)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if isinstance(item, (dict, list)):
            children = item.values() if isinstance(item, dict) else item
            if depth > 64 or nodes + len(pending) + len(children) > 65536:
                raise ValueError("Helm release exceeds structural bounds")
            pending.extend((child, depth + 1) for child in children)
    return release


def _secret_view(obj):
    if (
        set(obj) != {"apiVersion", "kind", "type", "metadata", "data"}
        or obj["apiVersion"] != "v1"
        or obj["kind"] != "Secret"
        or obj["type"] != "helm.sh/release.v1"
        or set(obj["data"]) != {"release"}
    ):
        raise ValueError("unsupported Helm storage object")
    meta = obj["metadata"]
    if set(meta) - {
        "name",
        "namespace",
        "labels",
        "uid",
        "resourceVersion",
        "creationTimestamp",
        "managedFields",
    }:
        raise ValueError("unsupported Helm storage metadata")
    release = _release(obj["data"]["release"])
    name, info, labels = release["name"], release["info"], meta["labels"]
    status = info["status"]
    if (
        set(release)
        - {"name", "namespace", "version", "chart", "config", "manifest", "hooks", "info"}
        or set(info) - (_DYNAMIC_INFO | {"deleted", "notes"})
        or ("notes" in info and not isinstance(info["notes"], str))
        or ("config" in release and not isinstance(release["config"], dict))
        or ("hooks" in release and not isinstance(release["hooks"], list))
        or re.fullmatch(_RELEASE_NAME, name) is None
        or meta["name"] != f"sh.helm.release.v1.{name}.v1"
        or release["namespace"] != meta["namespace"]
        or type(release["version"]) is not int
        or release["version"] != 1
        or not isinstance(release["chart"], dict)
        or not isinstance(release["manifest"], str)
        or info.get("deleted") != ""
        or status not in {"pending-install", "deployed", "failed"}
        or labels["name"] != name
        or labels["owner"] != "helm"
        or labels["status"] != status
        or labels["version"] != "1"
    ):
        raise ValueError("Helm release identity mismatch")
    time_label = "createdAt" if status == "pending-install" else "modifiedAt"
    if set(labels) != {"name", "owner", "version", "status", time_label} or not re.fullmatch(
        r"[0-9]{1,12}", labels[time_label]
    ):
        raise ValueError("invalid Helm storage labels")
    first = info["first_deployed"]
    if not _TIME.fullmatch(first) or info["last_deployed"] != first:
        raise ValueError("invalid Helm deployment timestamps")
    first_second = int(datetime.fromisoformat(first).timestamp())
    storage_second = int(labels[time_label])
    if storage_second < first_second or storage_second > 253402300799:
        raise ValueError("invalid Helm storage chronology")
    description = info["description"]
    if (
        (status == "pending-install" and description != "Initial install underway")
        or (status == "deployed" and description != "Install complete")
        or (status == "failed" and not description.startswith(f'Release "{name}" failed: '))
        or len(description.encode()) > 4096
    ):
        raise ValueError("invalid Helm status description")
    identity = {
        key: meta[key] for key in ("name", "namespace", "uid", "resourceVersion") if key in meta
    }
    for key in ("uid", "resourceVersion"):
        if key in identity and not _ID.fullmatch(identity[key]):
            raise ValueError("invalid API object identity")
    return {
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": identity,
        "release_name": name,
        "phase": status,
        "storage_second": storage_second,
        "content_sha256": release_content_sha256(release),
        "first_deployed_sha256": digest(first.encode()),
        "description_sha256": digest(description.encode()),
        "wire_sha256": digest({"type": obj["type"], "data": obj["data"], "labels": labels}),
    }


def secret_view(obj):
    try:
        return _secret_view(obj)
    except (
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        OverflowError,
        RecursionError,
        zlib.error,
    ):
        raise ValueError("invalid Helm release Secret") from None


def verify_submitted_secret(submitted, admitted):
    if not isinstance(submitted, dict) or not isinstance(submitted.get("metadata"), dict):
        raise ValueError("missing submitted Helm Secret")
    identity = admitted["metadata"]
    # Helm can omit the URL namespace and API-owned identifiers from its request.
    metadata = {"namespace": identity["namespace"]} | submitted["metadata"]
    projected = secret_view(submitted | {"metadata": metadata})
    if projected | {"metadata": identity} != admitted or any(
        identity.get(key) != value for key, value in projected["metadata"].items()
    ):
        raise ValueError("submitted Helm Secret differs from admission")


def prepare_helm_request(request, namespace, pins):
    for field, expected, original in (
        ("resource", _RESOURCE, "requestResource"),
        ("kind", _KIND, "requestKind"),
    ):
        if (
            any(
                {"group": ""} | request[key] != expected
                for key in (field, original)
                if key in request
            )
            or field not in request
        ):
            raise ValueError("unsupported Helm request conversion")
    uid, operation, username = (
        request.get("uid"),
        request.get("operation"),
        request.get("userInfo", {}).get("username"),
    )
    if (
        not isinstance(uid, str)
        or not _ID.fullmatch(uid)
        or operation not in ("CREATE", "UPDATE")
        or request.get("namespace") != namespace
        or not username
        or request.get("subResource")
        or request.get("requestSubResource")
        or request.get("dryRun") is not False
    ):
        raise ValueError("unsupported Helm storage operation")
    principal = digest(request["userInfo"])
    pin = next(
        (
            p
            for p in pins
            if p.principal_sha256 == principal
            and request.get("name") == f"sh.helm.release.v1.{p.release_name}.v1"
        ),
        None,
    )
    if pin is None:
        raise ValueError("unapproved Helm release or principal")
    obj = secret_view(request.get("object"))
    if (
        obj["metadata"]["namespace"] != namespace
        or obj["release_name"] != pin.release_name
        or obj["content_sha256"] != pin.content_sha256
    ):
        raise ValueError("unapproved Helm release content")
    old = None
    if operation == "CREATE":
        if request.get("oldObject") is not None or obj["phase"] != "pending-install":
            raise ValueError("expected pending Helm install")
    else:
        old = secret_view(request.get("oldObject"))
        if (
            obj["phase"] not in ("deployed", "failed")
            or old["phase"] != "pending-install"
            or old["metadata"] != obj["metadata"]
            or not old["metadata"].get("uid")
            or not old["metadata"].get("resourceVersion")
            or old["storage_second"] > obj["storage_second"]
            or old["content_sha256"] != obj["content_sha256"]
            or old["first_deployed_sha256"] != obj["first_deployed_sha256"]
            or (
                obj["phase"] == "failed"
                and obj["description_sha256"] != pin.failed_description_sha256
            )
        ):
            raise ValueError("unapproved Helm status transition")
    return {
        "uid": uid,
        "name": request["name"],
        "namespace": namespace,
        "operation": operation,
        "resource": _RESOURCE,
        "kind": _KIND,
        "object": obj,
        "oldObject": old,
        "principal_sha256": principal,
        "request_sha256": digest(request),
    }


def reserve_helm_slot(db, request):
    prefix = "helm-" + request["object"]["release_name"]
    if request["operation"] == "UPDATE":
        settled = db.execute(
            "SELECT json_extract(data,'$.evidence.object_uid'), "
            "json_extract(data,'$.evidence.resource_version'), "
            "json_extract(data,'$.request.object.wire_sha256') FROM ownership_slots "
            "JOIN intents ON uid=review_uid WHERE slot=? "
            "AND json_extract(data,'$.state')='settled'",
            (prefix + "-create",),
        ).fetchone()
        old = request["oldObject"]
        if settled != (
            old["metadata"]["uid"],
            old["metadata"]["resourceVersion"],
            old["wire_sha256"],
        ):
            raise ValueError("Helm status requires the settled Secret incarnation")
    slot = prefix + ("-create" if request["operation"] == "CREATE" else "-status")
    if db.execute("SELECT 1 FROM ownership_slots WHERE slot=?", (slot,)).fetchone():
        raise ValueError("Helm storage operation already reserved")
    db.execute("INSERT INTO ownership_slots VALUES (?, ?)", (slot, request["uid"]))
