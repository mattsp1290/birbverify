"""Authenticated account assertion subject and the sanitized durable result."""

from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, model_validator

from birbverify.contract import Commit, Id, Record, RequestId, Sha, digest
from birbverify.kubernetes_contract import Image, KubernetesBinding, Name

ImageRole = Literal["api", "ui", "openfga", "postgres", "busybox"]
Workload = Literal["api", "ui", "openfga", "application-postgres", "openfga-postgres"]
Outcome = Literal["passed", "failed", "unknown"]
StringDigest = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]
ContainerId = Annotated[str, Field(pattern=r"^(containerd|cri-o)://[a-f0-9]{64}$")]


class ImagePin(Record):
    reference: Image = Field(max_length=384)
    platform_manifest: StringDigest
    config_digest: StringDigest


class ReleaseArtifacts(Record):
    data_chart_sha256: Sha
    application_chart_sha256: Sha
    openfga_chart_sha256: Sha
    render_sha256: Sha


class ActivityRequest(Record):
    schema_version: Literal["birbverify.deployment.account-auth.request.v1"]
    request_id: RequestId
    workflow_id: Id
    repository: Literal["birbparty/birbparty"]
    candidate_revision: Commit
    authored_revision: Commit
    beans_issue: Id
    producer_revision: Commit
    policy_revision: Commit
    plan_sha256: Sha
    installation_sha256: Sha
    target: KubernetesBinding
    artifacts: ReleaseArtifacts
    images: dict[ImageRole, ImagePin] = Field(min_length=5, max_length=5)
    deadline: AwareDatetime


class Invocation(Record):
    request_id: RequestId
    request_sha256: Sha
    epoch: Id


class WorkerProfile(Record):
    verifier_identity: Id
    verifier_revision: Commit
    reviewer_identity: Id
    suite_sha256: Sha
    worker_cert_sha256: Sha
    temporal_server_ca_sha256: Sha
    temporal_namespace: Id
    task_queue: Id


class PodPin(Record):
    workload: Workload
    name: Name
    uid: Id
    controller_uid: Id
    node_name: Name
    node_uid: Id


class ActivityInstallation(Record):
    schema_version: Literal["birbverify.deployment.account-auth.installation.v1"]
    request: ActivityRequest
    profile: WorkerProfile
    webhook_name: Id
    pods: tuple[PodPin, ...] = Field(min_length=5, max_length=5)
    api_port: Annotated[int, Field(ge=1, le=65535)]

    @model_validator(mode="after")
    def exact_pods(self):
        for key in ("workload", "name", "uid"):
            if len({getattr(pod, key) for pod in self.pods}) != 5:
                raise ValueError("activity_requires_five_distinct_pods")
        if self.profile.verifier_revision != self.request.producer_revision:
            raise ValueError("worker_revision_mismatch")
        return self


class RunningContainer(Record):
    role: ImageRole
    name: Name
    runtime_image_digest: StringDigest
    container_id: ContainerId


class PodIncarnation(PodPin):
    containers: tuple[RunningContainer, ...] = Field(min_length=1, max_length=5)


class Assertions(Record):
    account_create: Outcome = "unknown"
    login_success: Outcome = "unknown"
    authenticated_identity: Outcome = "unknown"
    invalid_credentials_rejected: Outcome = "unknown"
    unauthenticated_access_rejected: Outcome = "unknown"


class ActivityResult(Record):
    schema_version: Literal["birbverify.deployment.account-auth.result.v1"]
    invocation: Invocation
    operation_id: Sha
    profile: WorkerProfile
    workloads: tuple[PodIncarnation, ...] = Field(max_length=5)
    started_at: AwareDatetime
    completed_at: AwareDatetime
    outcome: Outcome
    assertions: Assertions
    result_sha256: Sha

    @model_validator(mode="after")
    def validate_receipt(self):
        if digest(self.model_dump(mode="json", exclude={"result_sha256"})) != self.result_sha256:
            raise ValueError("result_digest_mismatch")
        if self.outcome == "passed" and (
            any(value != "passed" for value in self.assertions.model_dump().values())
            or len({pod.workload for pod in self.workloads}) != 5
        ):
            raise ValueError("incomplete_passing_result")
        return self
