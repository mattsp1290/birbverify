from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, model_validator

from birbverify.contract import Commit, Id, Manifest, Record, Request, RequestId, Sha, digest

Positive = Annotated[int, Field(gt=0, strict=True)]
ContainerId = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class Binding(Record):
    protocol: Literal["birbverify.target.v2"]
    target_id: Id
    target_incarnation: UUID


class Envelope(Binding):
    method: Id
    data: dict


class Authorization(Record):
    principal: Id
    workflow: Id
    policy_revision: Commit
    admission_target_incarnation: UUID
    closure_actor: Id
    grant_reference: Id


class BeginClosure(Record):
    contract_version: Literal["birbverify.closure.v1"] = "birbverify.closure.v1"
    closure_id: UUID
    target_id: Id
    target_incarnation: UUID
    request: Request
    request_sha256: Sha
    expected_attempt_id: Id | None
    expected_execution_epoch: Positive | None
    authorization: Authorization
    reason: Literal["dispatch_unknown", "reservation_reply_lost", "context_lost"]

    @model_validator(mode="after")
    def request_digest(self):
        if self.request_sha256 != digest(self.request):
            raise ValueError("request_digest_mismatch")
        return self


class OperationId(Record):
    target_incarnation: UUID
    closure_id: UUID
    step: Literal["fence", "stop", "cleanup", "release"]


class EvidenceRef(Record):
    id: Sha
    sha256: Sha
    kind: Literal["fence", "daemon", "stop", "registration", "restore"]
    checker_id: Id

    @model_validator(mode="after")
    def content_address(self):
        if self.id != self.sha256:
            raise ValueError("evidence_identity_mismatch")
        return self


class NeverAcquired(Record):
    kind: Literal["never_acquired"] = "never_acquired"
    attempt_id: None = None
    reservation_sha256: None = None


class Acquired(Record):
    kind: Literal["acquired"] = "acquired"
    attempt_id: Id
    reservation_sha256: Sha


Acquisition = Annotated[NeverAcquired | Acquired, Field(discriminator="kind")]


class NotStarted(Record):
    kind: Literal["not_started_target_confirmed"] = "not_started_target_confirmed"
    evidence_refs: tuple[EvidenceRef, ...] = Field(min_length=1)


class ConfirmedStop(Record):
    kind: Literal["confirmed"] = "confirmed"
    checker_id: Id
    evidence_refs: tuple[EvidenceRef, ...] = Field(min_length=1)


Stop = Annotated[NotStarted | ConfirmedStop, Field(discriminator="kind")]


class PresentHistory(Record):
    manifest_status: Literal["present"] = "present"
    manifest_sha256: Sha


class MissingHistory(Record):
    manifest_status: Literal["unavailable"] = "unavailable"
    manifest_sha256: None = None


History = Annotated[PresentHistory | MissingHistory, Field(discriminator="manifest_status")]


class Fence(Record):
    operation_id: OperationId
    commit_revision: Positive
    sealed_request_sha256: Sha
    effect_history_sha256: Sha
    evidence_ref: EvidenceRef


class Cleanup(Record):
    status: Literal["complete"] = "complete"
    procedure_sha256: Sha
    operation_id: OperationId
    payload_sha256: Sha
    result_sha256: Sha
    no_op_reason: Literal["never_acquired"] | None


class Release(Record):
    status: Literal["release_confirmed"] = "release_confirmed"
    operation_id: OperationId
    environment_revision: Positive


class ClosureReceipt(Record):
    contract_version: Literal["birbverify.closure.v1"] = "birbverify.closure.v1"
    producer_revision: Commit
    adapter_revision: Sha
    closure_actor: Id
    grant_reference: Id
    policy_revision: Commit
    committed_at: datetime
    closure_id: UUID
    command_sha256: Sha
    request_id: RequestId
    idempotency_key: Id
    request_sha256: Sha
    target_id: Id
    target_incarnation: UUID
    execution_epoch: Positive
    acquisition: Acquisition
    fence: Fence
    stop: Stop
    cleanup: Cleanup
    history: History
    release: Release
    receipt_sha256: Sha

    @model_validator(mode="after")
    def complete_digest(self):
        if self.receipt_sha256 != digest(self.model_dump(mode="json", exclude={"receipt_sha256"})):
            raise ValueError("receipt_digest_mismatch")
        if self.committed_at.tzinfo is None:
            raise ValueError("receipt_time_requires_timezone")
        for record, step in (
            (self.fence, "fence"),
            (self.cleanup, "cleanup"),
            (self.release, "release"),
        ):
            operation = record.operation_id
            if (
                operation.closure_id != self.closure_id
                or operation.target_incarnation != self.target_incarnation
                or operation.step != step
            ):
                raise ValueError("receipt_operation_binding_mismatch")
        if (self.acquisition.kind == "never_acquired") != (
            self.stop.kind == "not_started_target_confirmed"
        ):
            raise ValueError("receipt_acquisition_stop_mismatch")
        if self.fence.commit_revision >= self.release.environment_revision:
            raise ValueError("release_precedes_fence")
        return self


class ContainerGroup(Record):
    kind: Literal["docker_container"] = "docker_container"
    daemon_id: Annotated[str, Field(min_length=1, max_length=128)]
    host_boot_id: UUID
    container_id: ContainerId
    worker_pid: Positive
    worker_start_ticks: Positive
    config_sha256: Sha


class Registration(Record):
    worker_execution_id: Id
    target_id: Id
    target_incarnation: UUID
    launcher_id: Id
    group: ContainerGroup
    evidence_ref: EvidenceRef


class ReservationProvenance(Record):
    request_id: RequestId
    request_sha256: Sha
    execution_epoch: Positive
    admission_target_incarnation: UUID
    attempt_id: Id
    attempt_number: Literal[1] = 1
    prior_attempt_id: None = None
    acquired_at: datetime
    registration: Registration
    candidate_container: Id
    policy_sha256: Sha


class NoOwner(Record):
    kind: Literal["none"] = "none"


class AttemptOwner(Record):
    kind: Literal["attempt"] = "attempt"
    request_id: RequestId
    execution_epoch: Positive
    attempt_id: Id


class ClosureOwner(Record):
    kind: Literal["closure"] = "closure"
    request_id: RequestId
    execution_epoch: Positive
    closure_id: UUID


Owner = Annotated[NoOwner | AttemptOwner | ClosureOwner, Field(discriminator="kind")]


class Environment(Record):
    state: Literal["free", "active", "quarantined", "revoked"]
    owner: Owner
    candidate: Commit | None
    value: int

    @model_validator(mode="after")
    def free_has_no_owner(self):
        if self.state == "free" and self.owner.kind != "none":
            raise ValueError("free_target_has_owner")
        return self


class Progress(Record):
    closure_id: UUID
    execution_epoch: Positive
    acquisition: Acquisition
    phase: Literal["fenced_stop_unknown", "fenced_cleanup_unknown", "release_confirmed"]
    blocking_reason: Id | None
    fence: Fence
    stop: Stop | None
    cleanup: Cleanup | None
    receipt: ClosureReceipt | None

    @model_validator(mode="after")
    def release_has_receipt(self):
        if (self.phase == "release_confirmed") != (self.receipt is not None):
            raise ValueError("release_receipt_required")
        if self.phase == "fenced_stop_unknown" and (self.stop or self.cleanup):
            raise ValueError("unknown_stop_cannot_have_cleanup")
        if self.phase != "fenced_stop_unknown" and self.stop is None:
            raise ValueError("confirmed_stop_required")
        if self.acquisition.kind == "never_acquired" and (
            self.stop is None or self.stop.kind != "not_started_target_confirmed"
        ):
            raise ValueError("never_acquired_requires_target_stop")
        if self.acquisition.kind == "acquired" and self.stop and self.stop.kind != "confirmed":
            raise ValueError("acquired_requires_execution_stop")
        if self.receipt and (
            not self.cleanup
            or self.receipt.closure_id != self.closure_id
            or self.receipt.execution_epoch != self.execution_epoch
            or self.receipt.acquisition != self.acquisition
        ):
            raise ValueError("closure_receipt_binding_mismatch")
        return self


class RequestObservation(Record):
    request_id: RequestId
    request_sha256: Sha | None
    execution_epoch: Positive | None
    manifest: Manifest | None
    closure: Progress | None
    terminal: Literal["verification", "closed_without_verification"] | None


class Snapshot(Record):
    contract_version: Literal["birbverify.closure.v1"] = "birbverify.closure.v1"
    target_id: Id
    target_incarnation: UUID
    record_revision: Annotated[int, Field(ge=0, strict=True)]
    requests: tuple[RequestObservation, ...]
    environment: Environment


class HttpCommand(Record):
    method: Literal["GET", "POST", "DELETE"]
    path: Annotated[str, Field(min_length=1, max_length=1024)]
    body: dict | None


class LifecycleIntent(Record):
    operation_id: Id
    request_id: RequestId
    execution_epoch: Positive
    attempt_id: Id
    worker_execution_id: Id
    authority: Literal["worker", "closure"]
    closure_id: UUID | None
    verb: Literal["create", "start", "remove", "inspect", "wait", "logs", "list"]
    container: Annotated[str, Field(min_length=1, max_length=128)]
    command: HttpCommand
    arguments_sha256: Sha

    @model_validator(mode="after")
    def command_binding(self):
        if self.arguments_sha256 != digest(self.command):
            raise ValueError("arguments_digest_mismatch")
        if (self.authority == "closure") != (self.closure_id is not None):
            raise ValueError("closure_authority_mismatch")
        return self
