"""Bounded requests for the credentialed Kubernetes target gateway."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, model_validator

from birbverify.contract import Commit, Id, Record, RequestId, Sha, digest

Name = Annotated[str, Field(pattern=r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")]
Image = Annotated[str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9./:_-]*@sha256:[0-9a-f]{64}$")]


class KubernetesBinding(Record):
    target_id: Id
    cluster_uid: Id
    namespace: Name
    namespace_uid: Id


class KubernetesRequest(Record):
    schema_version: Literal["birbverify.kubernetes.v1"] = "birbverify.kubernetes.v1"
    request_id: RequestId = Field(max_length=63)
    candidate_revision: Commit
    producer_revision: Commit
    policy_revision: Commit
    plan_sha256: Sha
    target: KubernetesBinding
    image: Image
    deadline: datetime

    @model_validator(mode="after")
    def timezone_required(self):
        if self.deadline.tzinfo is None:
            raise ValueError("deadline must include timezone")
        return self


class KubernetesInstallation(Record):
    producer_revision: Commit
    policy_revision: Commit
    binding: KubernetesBinding
    pod_name: Name
    configmap_name: Name
    node_name: Name
    node_uid: Id
    pod_template: dict
    admission_specs: dict[str, Sha] = Field(min_length=4, max_length=4)


class KubernetesClosureReceipt(Record):
    schema_version: Literal["birbverify.kubernetes.closure.v1"]
    request_id: RequestId
    request_sha256: Sha
    candidate_revision: Commit
    producer_revision: Commit
    policy_revision: Commit
    plan_sha256: Sha
    image: Image
    installation_sha256: Sha
    pod_uid: str | None
    target: KubernetesBinding
    reason: Literal["completed", "cancelled", "worker_lost"]
    state: Literal["released"]
    terminal_proof: dict | None
    effects: dict
    operations_sha256: Sha


class KubernetesReceipt(KubernetesClosureReceipt):
    receipt_sha256: Sha

    @model_validator(mode="after")
    def receipt_digest(self):
        if self.receipt_sha256 != digest(self.model_dump(mode="json", exclude={"receipt_sha256"})):
            raise ValueError("receipt digest mismatch")
        return self
