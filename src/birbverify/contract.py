import hashlib
import json
from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Id = Annotated[str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}$")]
RequestId = Annotated[str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")]
Sha = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Commit = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]


def digest(value: BaseModel | dict | bytes) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    if not isinstance(value, bytes):
        value = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(value).hexdigest()


class Record(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Candidate(Record):
    repository: Id
    commit: Commit
    pr_head: Commit
    base: Commit
    kind: Literal["head", "integration"]
    artifact_sha256: Sha | None = None

    @model_validator(mode="after")
    def head_identity(self):
        if self.kind == "head" and self.commit != self.pr_head:
            raise ValueError("head candidate must equal PR head")
        return self


class Check(Record):
    id: Id
    assertion: Annotated[str, Field(min_length=1, max_length=512)]
    procedure_path: Literal["check.py"]
    procedure_revision: Commit
    procedure_sha256: Sha
    required_artifacts: tuple[Literal["observation", "command"], ...] = Field(min_length=1)


class Plan(Record):
    revision: Commit
    checks: tuple[Check, ...] = Field(min_length=1, max_length=8)
    cleanup: Literal["fixture-reset-v1"]

    @model_validator(mode="after")
    def unique_checks(self):
        if len({check.id for check in self.checks}) != len(self.checks):
            raise ValueError("duplicate check IDs")
        return self


class Authority(Record):
    principal: Id
    workflow: Id
    policy_revision: Commit
    environment: Id
    permitted_operations: tuple[Literal["fixture.apply", "fixture.reset"], ...]


class Resources(Record):
    capabilities: tuple[Id, ...]
    fixture: Literal["isolated-counter-v1"]
    timeout_seconds: Annotated[int, Field(ge=1, le=60)]
    max_attempts: Annotated[int, Field(ge=1, le=3)]
    deadline: datetime

    @model_validator(mode="after")
    def aware_deadline(self):
        if self.deadline.tzinfo is None:
            raise ValueError("deadline must include timezone")
        return self


class EvidencePolicy(Record):
    classification: Literal["private"]
    retention: Literal["fixture-local-until-owner-deletes-v1"]
    telemetry_correlation: Id


class Request(Record):
    contract_version: Literal["birbverify.v1"]
    request_id: RequestId
    goal_id: Id
    pull_request: Id
    correlation_id: Id
    idempotency_key: Id
    candidate: Candidate
    plan: Plan
    plan_sha256: Sha
    authority: Authority
    resources: Resources
    evidence: EvidencePolicy
    components: tuple[Id, ...]
    revision_method: Literal["git-archive-and-target-receipt-v1"]

    @model_validator(mode="after")
    def plan_identity(self):
        if self.plan_sha256 != digest(self.plan):
            raise ValueError("plan digest mismatch")
        return self


class Artifact(Record):
    id: Sha
    kind: Literal["observation", "command"]
    size: Annotated[int, Field(ge=0, le=65536)]
    sha256: Sha
    captured_at: datetime
    classification: Literal["private"]
    retention: Literal["fixture-local-until-owner-deletes-v1"]

    @model_validator(mode="after")
    def content_address(self):
        if self.id != self.sha256:
            raise ValueError("artifact identity must equal content digest")
        return self


class CheckRecord(Record):
    check_id: Id
    outcome: Literal["passed", "failed", "not_run", "inconclusive"]
    observation: Annotated[str, Field(max_length=1024)]
    duration_ms: Annotated[int, Field(ge=0)]
    artifacts: tuple[Artifact, ...]


class Manifest(Record):
    contract_version: Literal["birbverify.v1"]
    request_id: Id
    request_sha256: Sha
    attempt_id: Id
    attempt_number: Annotated[int, Field(ge=1, le=3)]
    retry_reason: Literal["initial", "infrastructure_recovery"]
    prior_attempt_id: Id | None
    correlation_id: Id
    telemetry_correlation: Id
    candidate: Candidate
    plan_sha256: Sha
    policy_revision: Commit
    environment: Id
    worker_id: Id
    worker_capabilities: tuple[Id, ...]
    tools: tuple[str, ...]
    started_at: datetime
    finished_at: datetime
    observed_before: Commit | None
    observed_after: Commit | None
    checks: tuple[CheckRecord, ...]
    operation_id: Id
    operation_reconciled: bool
    outcome: Literal["passed", "failed", "inconclusive", "cancelled", "superseded"]
    cleanup: Literal["complete", "failed", "unknown"]
    cancellation: Literal["none", "requested", "acknowledged"]
    termination: Literal["confirmed", "unknown"]
    environment_release: Literal["released", "retained", "quarantined"]
    reason: Literal[
        "checks_completed",
        "required_evidence_missing",
        "infrastructure_error",
        "worker_lost",
        "cancellation_acknowledged",
        "termination_unknown",
    ]

    @model_validator(mode="after")
    def consistent_result(self):
        if (
            self.started_at.tzinfo is None
            or self.finished_at.tzinfo is None
            or self.finished_at < self.started_at
        ):
            raise ValueError("invalid result timestamps")
        if len({check.check_id for check in self.checks}) != len(self.checks):
            raise ValueError("duplicate check records")
        if (self.attempt_number == 1) != (self.retry_reason == "initial"):
            raise ValueError("retry reason disagrees with attempt number")
        if (self.attempt_number == 1) != (self.prior_attempt_id is None):
            raise ValueError("predecessor disagrees with attempt number")
        if self.environment_release == "released" and (
            self.cleanup != "complete" or self.termination != "confirmed"
        ):
            raise ValueError("release requires confirmed stop and cleanup")
        if self.cancellation == "acknowledged" and (
            self.outcome != "cancelled"
            or self.termination != "confirmed"
            or self.cleanup != "complete"
        ):
            raise ValueError("cancellation acknowledgement requires stop and cleanup")
        if self.outcome == "passed" and (
            self.cancellation != "none"
            or self.termination != "confirmed"
            or self.cleanup != "complete"
            or self.environment_release != "released"
            or any(check.outcome != "passed" for check in self.checks)
        ):
            raise ValueError("inconsistent passed result")
        return self


def eligible(
    request: Request,
    result: Manifest,
    current: Candidate,
    read_artifact: Callable[[Artifact], bytes | None],
) -> bool:
    """Evidence completeness only. Birbforge owns the final delivery decision."""
    records = {check.check_id: check for check in result.checks}
    return (
        result.request_id == request.request_id
        and result.operation_id == f"{request.request_id}.apply"
        and result.correlation_id == request.correlation_id
        and result.telemetry_correlation == request.evidence.telemetry_correlation
        and all(
            (content := read_artifact(artifact)) is not None
            and len(content) == artifact.size
            and digest(content) == artifact.sha256
            for record in result.checks
            for artifact in record.artifacts
        )
        and result.request_sha256 == digest(request)
        and result.candidate == request.candidate == current
        and result.plan_sha256 == request.plan_sha256
        and result.policy_revision == request.authority.policy_revision
        and result.environment == request.authority.environment
        and result.finished_at <= request.resources.deadline
        and result.outcome == "passed"
        and result.cleanup == "complete"
        and result.termination == "confirmed"
        and result.environment_release == "released"
        and result.cancellation == "none"
        and result.observed_before == result.observed_after == current.commit
        and len(records) == len(result.checks) == len(request.plan.checks)
        and all(
            check.id in records
            and records[check.id].outcome == "passed"
            and set(check.required_artifacts).issubset(
                {artifact.kind for artifact in records[check.id].artifacts}
            )
            for check in request.plan.checks
        )
    )
